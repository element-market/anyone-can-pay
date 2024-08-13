#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper.h"
#include "secp256k1_lock.h"

#define OP_CANCEL 0
#define OP_BUY 1

#define MAX_PRICE 100000000000000000ULL // 1 billion ckb
#define CAPACITY_DIFFERENCE 8500000000ULL // 85 ckb
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
  uint64_t extra_data_length;
  uint8_t lock_hash[HASH_SIZE];
} listing_args_t;

// 0x8dbd23caa1387f636dec7db4077bd3f90552caf9d359a67c30b30c4da8d5a7b6
static uint8_t LISTING_CODE_HASH[32] = {
  0x8d, 0xbd, 0x23, 0xca, 0xa1, 0x38, 0x7f, 0x63, 0x6d, 0xec, 0x7d, 0xb4, 0x07, 0x7b, 0xd3, 0xf9, 0x05, 0x52, 0xca, 0xf9, 0xd3, 0x59, 0xa6, 0x7c, 0x30, 0xb3, 0x0c, 0x4d, 0xa8, 0xd5, 0xa7, 0xb6
};

// 0xce321b5ab5baf86c00ab8b44d68d1a6ff6196b8f
static uint8_t PUB_KEY_HASH[BLAKE160_SIZE] = {
  0xce, 0x32, 0x1b, 0x5a, 0xb5, 0xba, 0xf8, 0x6c, 0x00, 0xab, 0x8b, 0x44, 0xd6, 0x8d, 0x1a, 0x6f, 0xf6, 0x19, 0x6b, 0x8f
};

bool is_listing_script(uint8_t* code_hash, uint8_t hash_type) {
  return hash_type == 1 && memcmp(code_hash, LISTING_CODE_HASH, HASH_SIZE) == 0;
}

int get_code_hash_and_hash_type(void* script, uint64_t len, uint8_t** p_code_hash, uint8_t* p_hash_type) {
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;
  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return 1;
  }

  // Load code hash
  mol_seg_t code_hash_seg = MolReader_Script_get_code_hash(&script_seg);
  if (code_hash_seg.ptr == NULL || code_hash_seg.size != HASH_SIZE) {
    return 2;
  }
  *p_code_hash = code_hash_seg.ptr;

  // Load hash_type
  mol_seg_t hash_type_seg = MolReader_Script_get_hash_type(&script_seg);
  if (hash_type_seg.ptr == NULL || hash_type_seg.size != 1) {
    return 3;
  }
  *p_hash_type = *hash_type_seg.ptr;
  return 0;
}

// Require script.code_hash == LISTING_CODE_HASH && script.hash_type == 'type'
// Require script.code_hash == LISTING_CODE_HASH && script.hash_type == 'type'
int check_current_script(void* buffer) {
  uint64_t len = BUFFER_SIZE;
  if (ckb_checked_load_script(buffer, &len, 0) == CKB_SUCCESS) {
    uint8_t* code_hash;
    uint8_t hash_type;
    if (get_code_hash_and_hash_type(buffer, len, &code_hash, &hash_type) == 0) {
      return is_listing_script(code_hash, hash_type) ? 0 : 3;
    } else {
      return 2;
    }
  }
  return 1;
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
        return 1;
      }

      if (is_listing_inputs_ended) {
        // Listing inputs must be placed before other inputs
        if (is_listing_script(code_hash, hash_type)) {
          return 2;
        }
      } else {
        if (is_listing_script(code_hash, hash_type)) {
          listing_inputs_len++;
        } else {
          // Listing inputs is ended
          is_listing_inputs_ended = true;

          // Listing inputs cannot be empty
          if (listing_inputs_len == 0) {
            return 3;
          }
        }
      }
    } else {
      if (ret == CKB_LENGTH_NOT_ENOUGH) {
        return 4; // Load lock script error
      }
      break; // Ended
    }
    i++;
  }

  // At least one other_input is required
  if (listing_inputs_len >= i) {
    return 5;
  }

  *ptr_listing_inputs_len = listing_inputs_len;
  return 0;
}

int check_if_contains_first_input_lock_hash(void* buffer, bool* ptr_contains) {
  // Load current script hash
  uint64_t len = HASH_SIZE;
  if (ckb_checked_load_script_hash(buffer, &len, 0) != CKB_SUCCESS || len != HASH_SIZE) {
    return 1;
  }

  // Load inputs[0].lock_hash
  void* ptr_hash = buffer + 1 + HASH_SIZE;
  int ret = ckb_checked_load_cell_by_field(ptr_hash, &len, 0, 0, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return 2;
  }

  // Compare current script_hash and inputs[0].lock_hash
  *ptr_contains = memcmp(buffer, ptr_hash, HASH_SIZE) == 0;
  return 0;
}

int load_witness_data(void* buffer, witness_data_t* witness_data) {
  // Load witness[0]
  uint64_t len = BUFFER_SIZE;
  int ret = ckb_checked_load_witness(buffer, &len, 0, 0, CKB_SOURCE_INPUT);
  if (ret != CKB_SUCCESS || len == 0) {
    return 1;
  }

  witness_data->op_code = *(uint8_t *)buffer;
  if (witness_data->op_code == OP_CANCEL) {
    // 1 bytes(OP_CODE)
    return len == 1 ? 0 : 2;
  }

  if (witness_data->op_code == OP_BUY) {
    // 1 bytes(OP_CODE) + 2 bytes(platform_rate) + 2 bytes(royalty_rate) + 65 bytes(signature)
    if (len == 70) {
      uint8_t* ptr = buffer + 1;

      // Load and check platform_rate
      witness_data->platform_rate = (uint16_t)*ptr << 8 | (uint16_t)*(ptr + 1);
      if (witness_data->platform_rate > MAX_PLATFORM_RATE) {
        return 3;
      }

      // Load and check royalty_rate
      witness_data->royalty_rate = (uint16_t)*(ptr + 2) << 8 | (uint16_t)*(ptr + 3);
      if (witness_data->royalty_rate > MAX_ROYALTY_RATE) {
        return 4;
      }

      // Load signature
      memcpy((void *)witness_data->signature, (void *)(ptr + 4), SIGNATURE_SIZE);
      return 0;
    } else {
      return 5;
    }
  }
  return 6;  // Unknown op_code
}

bool isSegOutOfBounds(const mol_seg_t* inner_seg, const mol_seg_t* outer_seg) {
  if (inner_seg->ptr < outer_seg->ptr) {
    return true;
  }
  if ((inner_seg->ptr + inner_seg->size) > (outer_seg->ptr + outer_seg->size)) {
    return true;
  }
  return false;
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
    return 1;
  }

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)buffer;
  script_seg.size = len;

  // Read script.args
  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  if (args_seg.size < MOL_NUM_T_SIZE || isSegOutOfBounds(&args_seg, &script_seg)) {
    return 2;
  }
  mol_seg_t raw_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (raw_bytes_seg.size == 0 || isSegOutOfBounds(&raw_bytes_seg, &args_seg)) {
    return 3;
  }

  // Read price
  mol_seg_t price_seg = mol_table_slice_by_index(&raw_bytes_seg, 0);
  if (price_seg.size != 8 || isSegOutOfBounds(&price_seg, &raw_bytes_seg)) {
    return 4;
  }
  listing_args->price = *((uint64_t *)price_seg.ptr);

  // Read address bytes
  mol_seg_t address_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 1);
  if (address_bytes_seg.size < MOL_NUM_T_SIZE || isSegOutOfBounds(&address_bytes_seg, &raw_bytes_seg)) {
    return 5;
  }
  mol_seg_t raw_address_bytes_seg = MolReader_Bytes_raw_bytes(&address_bytes_seg);
  if (raw_address_bytes_seg.size < MOL_NUM_T_SIZE || isSegOutOfBounds(&raw_address_bytes_seg, &address_bytes_seg)) {
    return 6;
  }

  // Calc lock hash of address
  blake2b_init(blake2b_ctx_ptr, HASH_SIZE);
  blake2b_update(blake2b_ctx_ptr, raw_address_bytes_seg.ptr, raw_address_bytes_seg.size);
  if (blake2b_final(blake2b_ctx_ptr, listing_args->lock_hash, HASH_SIZE) != 0) {
    return 7;
  }

  // Read extra data length
  mol_seg_t extra_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 2);
  if (extra_bytes_seg.size < MOL_NUM_T_SIZE || isSegOutOfBounds(&extra_bytes_seg, &raw_bytes_seg)) {
    return 8;
  }
  mol_seg_t raw_extra_bytes_seg = MolReader_Bytes_raw_bytes(&extra_bytes_seg);
  if (isSegOutOfBounds(&raw_extra_bytes_seg, &extra_bytes_seg)) {
    return 9;
  }
  listing_args->extra_data_length = raw_extra_bytes_seg.size * 100000000ULL;
  return 0;
}

/**
 * Require: 1) inputs[n].lock_hash == inputs[i].lock_script.listing_args.lock_hash
 *          2) inputs[n].lock_hash == outputs[i].lock_hash
 *          3) inputs[i].capacity == outputs[i].capacity + CAPACITY_DIFFERENCE + listing_args.extra_data_length
 *          4) inputs[i].type_hash == outputs[i].type_hash
 *          5) inputs[i].data_hash == outputs[i].data_hash
 **/
int check_cancel(void* buffer, int listing_inputs_len) {
  int n = listing_inputs_len;
  uint8_t hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;

  // Load inputs[n].lock_hash
  int ret = ckb_checked_load_cell_by_field(hash, &len, 0, n, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return 1;
  }

  listing_args_t listing_args;
  blake2b_state blake2b_ctx;
  uint64_t input_capacity;
  uint64_t output_capacity;

  /**
   * Check inputs[n].lock_hash == inputs[i].lock_script.listing_args.lock_hash
   *       inputs[n].lock_hash == outputs[i].lock_hash
   *       inputs[i].capacity == outputs[i].capacity + CAPACITY_DIFFERENCE + listing_args.extra_data_length
   **/
  int i = 0;
  while (i < n) {
    // Load inputs[i].lock_script.listing_args
    if (get_input_listing_args(buffer, &blake2b_ctx, i, &listing_args) != 0) {
      return 2;
    }

    // Check if inputs[n].lock_hash == inputs[i].lock_script.listing_args.lock_hash
    if (memcmp(hash, listing_args.lock_hash, HASH_SIZE) != 0) {
      return 3;
    }

    // Load outputs[i].lock_hash
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return 4;
    }

    // Check if inputs[n].lock_hash == outputs[i].lock_hash
    if (memcmp(hash, buffer, HASH_SIZE) != 0) {
      return 5;
    }

    // Load inputs[i].capacity
    len = 8;
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&input_capacity), &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return 6;
    }

    // Load outputs[i].capacity
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&output_capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return 7;
    }

    // Check inputs[i].capacity == outputs[i].capacity + CAPACITY_DIFFERENCE + listing_args.extra_data_length
    if (input_capacity != output_capacity + CAPACITY_DIFFERENCE + listing_args.extra_data_length) {
      return 8;
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
    if (ret == CKB_ITEM_MISSING) {
      // Load outputs[i].type_hash
      len = HASH_SIZE;
      ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
      if (ret != CKB_ITEM_MISSING) {
        return 9;
      }
    } else if (ret == CKB_SUCCESS && len == HASH_SIZE) {
      // Load outputs[i].type_hash
      ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
      if (ret != CKB_SUCCESS || len != HASH_SIZE) {
        return 10;
      }
      
      // Check if input[i].type_hash == output[i].type_hash
      if (memcmp(hash, buffer, HASH_SIZE) != 0) {
        return 11;
      }
    } else {
      return 12;
    }

    // Load inputs[i].data_hash
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(hash, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_DATA_HASH);
    if (ret == CKB_ITEM_MISSING) {
      // Load outputs[i].data_hash
      len = HASH_SIZE;
      ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA_HASH);
      if (ret != CKB_ITEM_MISSING) {
        return 13;
      }
    } else if (ret == CKB_SUCCESS && len == HASH_SIZE) {
       // Load outputs[i].data_hash
      ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA_HASH);
      if (ret != CKB_SUCCESS || len != HASH_SIZE) {
        return 14;
      }

      // Check if input[i].data_hash == output[i].data_hash
      if (memcmp(hash, buffer, HASH_SIZE) != 0) {
        return 15;
      }
    } else {
      return 16;
    }

    i++;
  }

  return 0;
}

int check_signature(void* buffer, witness_data_t* witness_data) {
  // Load tx hash
  uint64_t len = HASH_SIZE;
  int ret = ckb_checked_load_tx_hash(buffer, &len, 0);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return 1;
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
    return 2;
  }

  // Validate signature
  ret = validate_signature(PUB_KEY_HASH, buffer, witness_data->signature);
  if (ret != 0) {
    return 3 + ret;
  }
  return 0;
}

/**
 * Require: 1) inputs[i].lock_script.listing_args.lock_hash == outputs[i].lock_hash
 *          2) outputs[i].capacity == price + CAPACITY_DIFFERENCE - fee
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
      return 1;
    }

    // Load outputs[i].lock_hash
    len = HASH_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return 2;  // error load outputs[i].lock_hash
    }

    // Check if inputs[i].lock_script.listing_args == outputs[i].lock_hash
    if (memcmp(listing_args.lock_hash, buffer, HASH_SIZE) != 0) {
      return 3;  // error outputs[i].lock_script
    }

     // Load outputs[i].capacity
    len = 8;
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return 4;  // error load outputs[i].capacity
    }

    // Check if price overflow
    if (listing_args.price > MAX_PRICE) {
      return 5;  // error price overflow
    }

    /**
     * Check outputs[i].capacity == price + capacity_difference - fee
     **/
    uint64_t capacity_difference = CAPACITY_DIFFERENCE + listing_args.extra_data_length;
    if (capacity != listing_args.price + capacity_difference - (listing_args.price / 10000 * fee_rate)) {
      return 6;  // error outputs[i].capacity
    }

    i++;
  }
  return 0;
}

int main() {
  int ret;
  unsigned char buffer[BUFFER_SIZE];

  // Require: current_script.code_hash == LISTING_CODE_HASH && current_script.hash_type == 'type'
  ret = check_current_script(buffer);
  if (ret != 0) {
    return 10 + ret;
  }

  // Require: listing inputs [0, n - 1] at the front
  //          other inputs [n, total_inputs_len - 1] at the back
  int listing_inputs_len;
  ret = check_and_calc_listing_inputs_len(buffer, &listing_inputs_len);
  if (ret != 0) {
    return 20 + ret;
  }

  // If inputs[0].lock_hash is included, perform all checks; otherwise, return success to save gas
  bool contains_first_input_lock_hash;
  ret = check_if_contains_first_input_lock_hash(buffer, &contains_first_input_lock_hash);
  if (ret != 0) {
    return 30 + ret;
  }
  if (!contains_first_input_lock_hash) {
    return 0;
  }

  // Load witness data
  witness_data_t witness_data;
  ret = load_witness_data(buffer, &witness_data);
  if (ret != 0) {
    return 40 + ret;
  }

  if (witness_data.op_code == OP_CANCEL) {
    ret = check_cancel(buffer, listing_inputs_len);
    if (ret != 0) {
      return 50 + ret;
    }
  } else {
    // Check signature
    ret = check_signature(buffer, &witness_data);
    if (ret != 0) {
      return 70 + ret;
    }

    // Check buy
    uint16_t fee_rate = witness_data.platform_rate + witness_data.royalty_rate;
    ret = check_buy(buffer, fee_rate, listing_inputs_len);
    if (ret != 0) {
      return 80 + ret;
    }
  }
  return 0;
}
