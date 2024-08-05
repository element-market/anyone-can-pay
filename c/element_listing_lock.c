#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper.h"
#include "secp256k1_lock.h"

#define OP_CANCEL 0
#define OP_BUY 1

#define MAX_PRICE 100000000000000000ULL // 1 billion ckb
#define CAPACITY_DIFFERENCE 6100000000ULL // 61 ckb
#define MAX_PLATFORM_RATE 500   // 5%
#define MAX_ROYALTY_RATE 1000   // 10%

typedef struct {
  uint8_t op_code;
  uint16_t platform_rate;
  uint16_t royalty_rate;
  unsigned char signature[SIGNATURE_SIZE];
} witness_data_t;

typedef struct {
  uint64_t price;
  uint8_t lock_hash[HASH_SIZE];
} listing_args_t;

// 0x27628f025b0f2228c8562abfec6897b65bf34f5e18bf01e7ebf29e8c71b8ccaf
static uint8_t LISTING_CODE_HASH[32] = {
	0x27, 0x62, 0x8f, 0x02, 0x5b, 0x0f, 0x22, 0x28, 0xc8, 0x56, 0x2a, 0xbf, 0xec, 0x68, 0x97, 0xb6, 0x5b, 0xf3, 0x4f, 0x5e, 0x18, 0xbf, 0x01, 0xe7, 0xeb, 0xf2, 0x9e, 0x8c, 0x71, 0xb8, 0xcc, 0xaf
};

// 
static uint8_t PUB_KEY[BLAKE160_SIZE] = {
};

bool is_listing_script(uint8_t* code_hash, uint8_t hash_type) {
  return hash_type == 0 && memcmp(code_hash, LISTING_CODE_HASH, HASH_SIZE) == 0;
}

int get_code_hash_and_hash_type(void* script, uint64_t len, uint8_t** p_code_hash, uint8_t* p_hash_type) {
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return -1;
  }

  // Load code hash
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  if (code_hash_seg.ptr == NULL || code_hash_seg.size != HASH_SIZE) {
    return -2;
  }
  *p_code_hash = code_hash_seg.ptr;

  // Load hash_type
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
  if (hash_type_seg.ptr == NULL || hash_type_seg.size != 1) {
    return -3;
  }
  *p_hash_type = *hash_type_seg.ptr;
  return 0;
}

// Require script.code_hash == LISTING_CODE_HASH && script.hash_type == 'type'
bool check_current_script(void* buffer) {
  uint64_t len = BUFFER_SIZE;
  if (ckb_checked_load_script(buffer, &len, 0) == CKB_SUCCESS) {
    uint8_t* code_hash;
    uint8_t hash_type;
    if (get_code_hash_and_hash_type(buffer, len, &code_hash, &hash_type) == 0) {
      return is_listing_script(code_hash, hash_type);
    }
  }
  return false;
}
 
/**
 * Require: listing inputs [0, n - 1] at the front
 *          other inputs [n, total_inputs_len - 1] at the back
 */
int check_and_calc_listing_inputs_len(void* buffer, int* ptr_listing_inputs_len) {
  int ret;
  uint64_t len;
  uint8_t* code_hash;
  uint8_t hash_type;

  int i = 0;
  int listing_inputs_len = 0;
  bool is_listing_inputs_ended = false;

  while (true) {
    // Load inputs[i].lock_script
    len = BUFFER_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK);
    if (ret == CKB_SUCCESS) {
      // Load inputs[i].lock_script.code_hash and hash_type 
      if (get_code_hash_and_hash_type(buffer, len, &code_hash, &hash_type) != 0) {
        return -1;  
      }
      
      if (is_listing_inputs_ended) {
        // Listing inputs must be placed before other inputs
        if (is_listing_script(code_hash, hash_type)) {
          return -2;  
        }
      } else {
        if (is_listing_script(code_hash, hash_type)) {
          listing_inputs_len++;
        } else {
          // Listing inputs is ended
          is_listing_inputs_ended = true;

          // Listing inputs cannot be empty
          if (listing_inputs_len == 0) {
            return -3;
          }
        }
      }
    } else {
      if (ret == CKB_LENGTH_NOT_ENOUGH) {
        return -1; // Load lock script error
      }
      break; // Ended
    }
    i++;
  }

  // At least one other_input is required
  if (listing_inputs_len >= i) {
    return -5;
  }

  *ptr_listing_inputs_len = listing_inputs_len;
  return 0;
}

int check_if_contains_first_input_lock_hash(void* buffer, bool* ptr_contains) {
  // Load current script hash
  uint64_t len = HASH_SIZE;
  if (ckb_checked_load_script_hash(buffer, &len, 0) != CKB_SUCCESS || len != HASH_SIZE) {
    return -1;
  }

  // Load inputs[0].lock_hash
  void* ptr_hash = buffer + 1 + HASH_SIZE;
  int ret = ckb_checked_load_cell_by_field(ptr_hash, &len, 0, 0, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return -2;
  }

  // Compare current script_hash and inputs[0].lock_hash
  *ptr_contains = memcmp(buffer, ptr_hash, HASH_SIZE) == 0;
  return 0;
}

int load_witness_data(void* buffer, witness_data_t* witness_data) {
  // Load witness[0]
  uint64_t len = BUFFER_SIZE;
  int ret = ckb_checked_load_witness(buffer, &len, 0, 0, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS) {
    return -1;
  }

  // Extract witness lock bytes
  mol_seg_t witness_lock_seg;
  ret = extract_witness_lock(buffer, len, &witness_lock_seg);
  if (ret != CKB_SUCCESS) {
    return -2;
  }
  if (witness_lock_seg.size == 0) {
    return -3;  // Error size
  }

  witness_data->op_code = *witness_lock_seg.ptr;
  if (witness_data->op_code == OP_CANCEL) {
    // 1 bytes(OP_CODE)
    return witness_lock_seg.size == 1 ? 0 : -3;
  }

  if (witness_data->op_code == OP_BUY) {
    // 1 bytes(OP_CODE) + 2 bytes(platform_rate) + 2 bytes(royalty_rate) + 65 bytes(signature)
    if (witness_lock_seg.size == 70) {
      uint8_t* ptr = witness_lock_seg.ptr + 1;

      // Load and check platform_rate
      witness_data->platform_rate = (uint16_t)*ptr << 8 | (uint16_t)*(ptr + 1);
      if (witness_data->platform_rate > MAX_PLATFORM_RATE) {
        return -4;
      }

      // Load and check royalty_rate
      witness_data->royalty_rate = (uint16_t)*(ptr + 2) << 8 | (uint16_t)*(ptr + 3);
      if (witness_data->royalty_rate > MAX_ROYALTY_RATE) {
        return -5;
      }

      // Load signature
      memcpy((void *)witness_data->signature, (void *)(ptr + 4), SIGNATURE_SIZE);
      return 0;
    } else {
      return -3;
    }
  }
  return -6;  // Unknown op_code
}

int get_input_listing_args(
  void* buffer, 
  blake2b_state* blake2b_ctx_ptr, 
  size_t input_index, 
  listing_args_t* listing_args
) {
  // Load inputs[i].lock_script
  uint64_t len = BUFFER_SIZE;
  if (ckb_checked_load_cell_by_field(buffer, &len, 0, input_index, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK) != 0) {
    return -1;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)buffer;
  script_seg.size = len;

  // lLad script.args
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  if (args_seg.ptr == NULL || args_seg.size == 0) {
    return -2;
  }

  // Parse raw args bytes
  mol_seg_t args_raw_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_raw_seg.ptr == NULL || args_raw_seg.size < 8) {
    return -3;
  }

  // 8 bytes[price] + x bytes[payee lock script]
  uint64_t price = 0;
  for (size_t i = 0; i < 8; i++) {
    price = (price << 8) | (uint64_t)(args_raw_seg.ptr[i]);
  }
  listing_args->price = price;

  // Calculate the payee lock_hash
  blake2b_init(blake2b_ctx_ptr, HASH_SIZE);
  blake2b_update(blake2b_ctx_ptr, args_raw_seg.ptr + 8, args_raw_seg.size - 8);
  if (blake2b_final(blake2b_ctx_ptr, listing_args->lock_hash, HASH_SIZE) != 0) {
    return -4;
  }
  return 0;
}

/** 
 * Require: 1) inputs[n].lock_hash == inputs[i].lock_script.listing_args.lock_hash
 *          2) inputs[n].lock_hash == outputs[i].lock_hash 
 *          3) inputs[i].type_hash == outputs[i].type_hash
 *          4) inputs[i].data_hash == outputs[i].data_hash
 *          5) inputs[i].capacity == outputs[i].capacity + CAPACITY_DIFFERENCE
 **/
int check_cancel(void* buffer, int listing_inputs_len) {
  int n = listing_inputs_len;
  uint8_t hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;

  // Load inputs[n].lock_hash
  int ret = ckb_checked_load_cell_by_field(hash, &len, 0, n, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return -1;
  }

  /** 
   * Check inputs[n].lock_hash == inputs[i].lock_script.listing_args.lock_hash
   *       inputs[n].lock_hash == outputs[i].lock_hash
   **/
  int i = 0;
  listing_args_t listing_args;
  blake2b_state blake2b_ctx;
  while (i < n) {
    // Load inputs[i].lock_script.listing_args
    if (get_input_listing_args(buffer, &blake2b_ctx, i, &listing_args) != 0) {
      return -2;
    }

    // Check if inputs[n].lock_hash == inputs[i].lock_script.listing_args.lock_hash
    if (memcmp(hash, listing_args.lock_hash, HASH_SIZE) != 0) {
      return -3;
    }
    
    // Load outputs[i].lock_hash
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return -4;
    }

    // Check if inputs[n].lock_hash == outputs[i].lock_hash
    if (memcmp(hash, buffer, HASH_SIZE) != 0) {
      return -5;
    }

    i++;
  }

  /** 
   * Check inputs[i].type_hash == outputs[i].type_hash
   *       inputs[i].data_hash == outputs[i].data_hash
   **/
  i = 0;
  while (i < n) {
    // Load inputs[i].type_hash
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(hash, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return -6;
    }

    // Load outputs[i].type_hash
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return -7;
    }

    // Check if input[i].type_hash == output[i].type_hash
    if (memcmp(hash, buffer, HASH_SIZE) != 0) {
      return -8;
    }

    // Load inputs[i].data_hash
    ret = ckb_checked_load_cell_by_field(hash, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_DATA_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return -9;
    }

    // Load outputs[i].data_hash
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return -10;
    }

    // Check if input[i].data_hash == output[i].data_hash
    if (memcmp(hash, buffer, HASH_SIZE) != 0) {
      return -11;
    }

    i++;
  }

  /** 
   * Check inputs[i].capacity == outputs[i].capacity + CAPACITY_DIFFERENCE
   **/
  i = 0;
  uint64_t input_capacity;
  uint64_t output_capacity;
  while (i < n) {
    len = 8;

    // Load inputs[i].capacity
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&input_capacity), &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return -12;
    }

    // Load outputs[i].capacity
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&output_capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return -13;
    }

    // Check if inputs[i].capacity == outputs[i].capacity + CAPACITY_DIFFERENCE
    if (input_capacity != output_capacity + CAPACITY_DIFFERENCE) {
      return -14;
    }

    i++;
  }

  return 0;
}

int check_signature(void* buffer, witness_data_t* witness_data) {
  // Load tx hash
  uint64_t len = HASH_SIZE;
  int ret = ckb_load_tx_hash(buffer, &len, 0);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return -10;
  }

  // message = 32 bytes(tx_hash) + 1 bytes(op_code) + 2 bytes(platform_rate) + 2 bytes(royalty_rate)
  uint8_t* ptr = (uint8_t*)(buffer + HASH_SIZE);
  *ptr = witness_data->op_code;
  *(ptr + 1) = (uint8_t)(witness_data->platform_rate >> 8);
  *(ptr + 2) = (uint8_t)(witness_data->platform_rate & 0xff);
  *(ptr + 3) = (uint8_t)(witness_data->royalty_rate >> 8);
  *(ptr + 4) = (uint8_t)(witness_data->royalty_rate & 0xff);

  // Calc message hash
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, HASH_SIZE);
  blake2b_update(&blake2b_ctx, buffer, HASH_SIZE + 5);
  if (blake2b_final(&blake2b_ctx, buffer, HASH_SIZE) != 0) {
    return -20;
  }

  // Validate signature
  ret = validate_signature(PUB_KEY, buffer, witness_data->signature);
  if (ret != 0) {
    return -30 + ret;
  }
  return 0;
}

/** 
 * Require: 1) inputs[i].lock_script.listing_args.lock_hash == outputs[i].lock_hash
 *          2) outputs[i].capacity <= price + CAPACITY_DIFFERENCE 
 *          3) outputs[i].capacity >= price + CAPACITY_DIFFERENCE - fee
 **/
int check_buy(void* buffer, uint16_t fee_rate, int listing_inputs_len) {
  int ret;
  uint64_t len;
  uint64_t capacity;
  listing_args_t listing_args;
  blake2b_state blake2b_ctx;

  int i = 0;
  while (i < listing_inputs_len) {
    // Load inputs[i].lock_script.listing_args
    if (get_input_listing_args(buffer, &blake2b_ctx, i, &listing_args) != 0) {
      return -1; 
    }
    
    // Load outputs[i].lock_hash
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return -2;  // error load outputs[i].lock_hash
    }

    // Check if inputs[i].lock_script.listing_args == outputs[i].lock_hash
    if (memcmp(listing_args.lock_hash, buffer, HASH_SIZE) != 0) {
      return -3;  // error outputs[i].lock_script
    }

     // Load outputs[i].capacity
    len = 8;
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return -4;  // error load outputs[i].capacity
    }

    // Check if price overflow
    if (listing_args.price > MAX_PRICE) {
      return -5;  // error price overflow
    }

    /** 
     * Check outputs[i].capacity <= price + CAPACITY_DIFFERENCE
     *       outputs[i].capacity >= price + CAPACITY_DIFFERENCE - fee
     **/
    if (
      capacity > listing_args.price + CAPACITY_DIFFERENCE ||
      capacity < listing_args.price + CAPACITY_DIFFERENCE - (listing_args.price / 10000 * fee_rate)
    ) {
      return -6;  // error outputs[i].capacity
    }

    i++;
  }
  return 0;
}

int main() {
  int ret;
  unsigned char buffer[BUFFER_SIZE];

  // Require: current_script.code_hash == LISTING_CODE_HASH && current_script.hash_type == 'type'
  if (!check_current_script(buffer)) {
    return -100;
  }

  // Require: listing inputs [0, n - 1] at the front
  //          other inputs [n, total_inputs_len - 1] at the back
  int listing_inputs_len;
  ret = check_and_calc_listing_inputs_len(buffer, &listing_inputs_len);
  if (ret != 0) {
    return -200 + ret;
  }

  // If inputs[0].lock_hash is included, perform all checks; otherwise, return success to save gas
  bool contains_first_input_lock_hash;
  ret = check_if_contains_first_input_lock_hash(buffer, &contains_first_input_lock_hash);
  if (ret != 0) {
    return -300 + ret;
  }
  if (!contains_first_input_lock_hash) {
    return 0;
  }
  
  // Load witness data
  witness_data_t witness_data;
  ret = load_witness_data(buffer, &witness_data);
  if (ret != 0) {
    return -400 + ret;
  }

  if (witness_data.op_code == OP_CANCEL) {
    ret = check_cancel(buffer, listing_inputs_len);
    if (ret != 0) {
      return -500 + ret;
    }
  } else {
    // Check signature
    ret = check_signature(buffer, &witness_data);
    if (ret != 0) {
      return -600 + ret;
    }

    // Check buy
    uint16_t fee_rate = witness_data.platform_rate + witness_data.royalty_rate;
    ret = check_buy(buffer, fee_rate, listing_inputs_len);
    if (ret != 0) {
      return -700 + ret;
    }
  }
  return 0;
}