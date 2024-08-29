#include "element_config.h"
#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper.h"
#include "secp256k1_lock.h"

#define OP_CANCEL 0
#define OP_BUY 1
#define OP_SELL 2

#define ORDER_SIDE_OFFER 0
#define ORDER_SIDE_LISTING 1

#define OFFER_COLLECTION 0
#define OFFER_ITEM 1

#define CKB_UNIT 100000000ULL
#define MAX_GAS 1000000000ULL // 10 ckb
#define MAX_PRICE 100000000000000000ULL // 1 billion ckb
#define CAPACITY_DIFFERENCE 8600000000ULL // 86 ckb

#define MAX_PLATFORM_RATE 500   // 5%
#define MAX_ROYALTY_RATE 1000   // 10%

typedef struct {
  uint8_t op_code;
  uint16_t platform_rate;
  uint16_t royalty_rate;
  unsigned char signature[SIGNATURE_SIZE];
} witness_data_t;

typedef struct {
  uint8_t lock_hash[HASH_SIZE];
} cancel_args_t;

typedef struct {
  uint64_t price;
  uint64_t refund_capacity;
  uint8_t lock_hash[HASH_SIZE];
} listing_args_t;

typedef struct {
  uint8_t asset_type;
  uint8_t offer_type;
  uint8_t asset_id[HASH_SIZE];
  uint8_t lock_hash[HASH_SIZE];
  uint64_t price;
} offer_args_t;

static bool is_not_seg_tail(const mol_seg_t* inner_seg, const mol_seg_t* outer_seg);
static int get_cancel_args(void* buffer, blake2b_state* blake2b_ctx_ptr, size_t input_index, cancel_args_t* args);
static int get_listing_args(void* buffer, blake2b_state* blake2b_ctx_ptr, size_t input_index, listing_args_t* args);
static int get_offer_args(void* buffer, blake2b_state* blake2b_ctx_ptr, size_t input_index, offer_args_t* args);
static int load_cluster_id_from_cell_data(void* buffer, int index, uint8_t** ptr_cluster_id);
static int check_gas();

bool is_element_lock_script(uint8_t* code_hash, uint8_t hash_type) {
  return hash_type == 1 && memcmp(code_hash, ELEMENT_LOCK_CODE_HASH, HASH_SIZE) == 0;
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

// Require script.code_hash == ELEMENT_LOCK_CODE_HASH && script.hash_type == 'type'
// Require script.code_hash == ELEMENT_LOCK_CODE_HASH && script.hash_type == 'type'
int check_current_script(void* buffer) {
  uint64_t len = BUFFER_SIZE;
  if (ckb_checked_load_script(buffer, &len, 0) == CKB_SUCCESS) {
    uint8_t* code_hash;
    uint8_t hash_type;
    if (get_code_hash_and_hash_type(buffer, len, &code_hash, &hash_type) == 0) {
      return is_element_lock_script(code_hash, hash_type) ? 0 : 3;
    } else {
      return 2;
    }
  }
  return 1;
}

/**
 * Require: order inputs [0, n - 1] at the front
 *          other inputs [n, total_inputs_len - 1] at the back
 */
int check_and_calc_order_inputs_len(void* buffer, int* ptr_order_inputs_len) {
  int ret;
  uint64_t len;
  uint8_t* code_hash;
  uint8_t hash_type;

  int i;
  int order_inputs_len = 0;
  bool is_order_inputs_ended = false;

  for (i = 0; ; i++) {
    // Load inputs[i].lock_script
    len = BUFFER_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK);
    if (ret == CKB_SUCCESS) {
      // Load inputs[i].lock_script.code_hash and hash_type
      if (get_code_hash_and_hash_type(buffer, len, &code_hash, &hash_type) != 0) {
        return 1;
      }

      if (is_order_inputs_ended) {
        // Order inputs must be placed before other inputs
        if (is_element_lock_script(code_hash, hash_type)) {
          return 2;
        }
      } else {
        if (is_element_lock_script(code_hash, hash_type)) {
          order_inputs_len++;
        } else {
          // Order inputs is ended
          is_order_inputs_ended = true;

          // Order inputs cannot be empty
          if (order_inputs_len == 0) {
            return 3;
          }
        }
      }
    } else if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break; // Ended
    } else {
      return 4; // Load script error
    }
  }

  // At least one other_input is required
  if (order_inputs_len >= i) {
    return 5;
  }

  *ptr_order_inputs_len = order_inputs_len;
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
  int ret = ckb_load_cell_by_field(ptr_hash, &len, 0, 0, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
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

  if (witness_data->op_code == OP_BUY || witness_data->op_code == OP_SELL) {
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
      memcpy(witness_data->signature, ptr + 4, SIGNATURE_SIZE);
      return 0;
    } else {
      return 5;
    }
  }
  return 6;  // Unknown op_code
}

/**
 * Require: 1) inputs[n].lock_hash == inputs[i].lock_script.order_args.lock_hash
 *          2) inputs[n].lock_hash == outputs[i].lock_hash
 *          3) inputs[i].type_hash == outputs[i].type_hash
 *          4) inputs[i].data_hash == outputs[i].data_hash
 **/
int check_cancel(void* buffer, int order_inputs_len) {
  int n = order_inputs_len;
  uint8_t hash[HASH_SIZE];
  uint64_t len = HASH_SIZE;

  // Load inputs[n].lock_hash
  int ret = ckb_load_cell_by_field(hash, &len, 0, n, CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);
  if (ret != CKB_SUCCESS || len != HASH_SIZE) {
    return 1;
  }

  cancel_args_t order_args;
  blake2b_state blake2b_ctx;

  /**
   * Check inputs[n].lock_hash == inputs[i].lock_script.order_args.lock_hash
   **/
  int i;
  for (i = 0; i < n; i++) {
    // Load inputs[i].lock_script.order_args
    if (get_cancel_args(buffer, &blake2b_ctx, i, &order_args) != 0) {
      return 2;
    }
    // Check inputs[n].lock_hash == inputs[i].lock_script.order_args.lock_hash
    if (memcmp(hash, order_args.lock_hash, HASH_SIZE) != 0) {
      return 3;
    }
  }

  /**
   * Check inputs[n].lock_hash == outputs[i].lock_hash
   **/
  for (i = 0; ; i++) {
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_SUCCESS && len == HASH_SIZE) {
      // Check inputs[n].lock_hash == outputs[i].lock_hash
      if (memcmp(hash, buffer, HASH_SIZE) != 0) {
        return 4;
      }
    } else if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;  // Ended
    } else {
      return 5; // Load lock_hash error
    }
  }

  /**
   * Check inputs[i].type_hash == outputs[i].type_hash
   *       inputs[i].data_hash == outputs[i].data_hash
   **/
  for (i = 0; i < n; i++) {
    // Load inputs[i].type_hash
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(hash, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH);
    if (ret == CKB_ITEM_MISSING) {
      // Load outputs[i].type_hash
      len = HASH_SIZE;
      ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
      if (ret != CKB_ITEM_MISSING) {
        return 6;
      }
    } else if (ret == CKB_SUCCESS && len == HASH_SIZE) {
      // Load outputs[i].type_hash
      ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE_HASH);
      if (ret != CKB_SUCCESS || len != HASH_SIZE) {
        return 7;
      }

      // Check if input[i].type_hash == output[i].type_hash
      if (memcmp(hash, buffer, HASH_SIZE) != 0) {
        return 8;
      }
    } else {
      return 9;
    }

    // Load inputs[i].data_hash
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(hash, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_DATA_HASH);
    if (ret == CKB_SUCCESS && len == HASH_SIZE) {
      // Load outputs[i].data_hash
      ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_DATA_HASH);
      if (ret != CKB_SUCCESS || len != HASH_SIZE) {
        return 10;
      }

      // Check if input[i].data_hash == output[i].data_hash
      if (memcmp(hash, buffer, HASH_SIZE) != 0) {
        return 11;
      }
    } else {
      return 12;
    }
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
 * Require: 1) inputs[i].lock_script.order_args.lock_hash == outputs[i].lock_hash
 *          2) outputs[i].capacity == price + capacity_difference - fee
 **/
int check_buy(void* buffer, uint16_t fee_rate, int order_inputs_len) {
  int ret;
  uint64_t len;
  uint64_t input_capacity;
  uint64_t input_occupied_capacity;
  uint64_t capacity_difference;
  uint64_t output_capacity;
  listing_args_t order_args;
  blake2b_state blake2b_ctx;

  for (int i = 0; i < order_inputs_len; i++) {
    // Load inputs[i].lock_script.order_args
    if (get_listing_args(buffer, &blake2b_ctx, i, &order_args) != 0) {
      return 1;
    }

    // Check price
    if (order_args.price > MAX_PRICE) {
      return 2;  // error price overflow
    }

    // Load outputs[i].lock_hash
    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (ret != CKB_SUCCESS || len != HASH_SIZE) {
      return 3;  // error load outputs[i].lock_hash
    }

    // Check if inputs[i].lock_script.order_args.lock_hash == outputs[i].lock_hash
    if (memcmp(order_args.lock_hash, buffer, HASH_SIZE) != 0) {
      return 4;  // error outputs[i].lock_script
    }

    // Load inputs[i].capacity
    len = 8;
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&input_capacity), &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return 5;  // error load inputs[i].capacity
    }

    // Load inputs[i].occupied_capacity
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&input_occupied_capacity), &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_OCCUPIED_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return 6;  // error load inputs[i].occupied_capacity
    }

    // Load outputs[i].capacity
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&output_capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret != CKB_SUCCESS || len != 8) {
      return 7;  // error load outputs[i].capacity
    }

    /**
     * Check outputs[i].capacity == price + capacity_difference - fee
     **/
    capacity_difference = order_args.refund_capacity + input_capacity - input_occupied_capacity - CKB_UNIT;
    if (
      output_capacity != order_args.price + capacity_difference - (order_args.price / 10000 * fee_rate)
    ) {
      return 8;  // error outputs[i].capacity
    }
  }
  return 0;
}

/**
 * Require: 1) inputs[i].data == '0x' && inputs[i].type_script == null
 *          2) inputs[i].lock_script.order_args.lock_hash == outputs[i].lock_hash
 *          3) outputs[i].type_script.code_hash == order_args.code_hash
 *          4) outputs[i].type_script.hash_type == order_args.hash_type
 *          5) if offer item : outputs[i].type_script.args = order_args.asset_id
 *          6) if offer collection ; outputs[i].data.cluster_id = order_args.asset_id
 **/
int check_sell(void* buffer, int order_inputs_len) {
  int ret;
  uint64_t len;

  /**
   * Check inputs[i].data == '0x' && inputs[i].type_script == null
   **/
  int i;
  for (i = 0; i < order_inputs_len; i++) {
    len = 0;
    ret = ckb_load_cell_data((void *)0, &len, 0, i, CKB_SOURCE_INPUT);
    if (ret != CKB_SUCCESS || len != 0) {
      return 1; // inputs[i].data != '0x'
    }

    len = HASH_SIZE;
    ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_TYPE_HASH);
    if (ret != CKB_ITEM_MISSING) {
      return 2; // inputs[i].type_script != null
    }
  }

  offer_args_t order_args;
  blake2b_state blake2b_ctx;
  for (i = 0; i < order_inputs_len; i++) {
    // Load inputs[i].lock_script.order_args
    if (get_offer_args(buffer, &blake2b_ctx, i, &order_args) != 0) {
      return 3;   // error load inputs[i].lock_script.order_args
    }

    /**
     * Check inputs[i].lock_script.order_args.lock_hash == outputs[i].lock_hash
     **/
    {
      // Load outputs[i].lock_hash
      len = HASH_SIZE;
      ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
      if (ret != CKB_SUCCESS || len != HASH_SIZE) {
        return 4;  // error load outputs[i].lock_hash
      }

      // Check inputs[i].lock_script.order_args.lock_hash == outputs[i].lock_hash
      if (memcmp(order_args.lock_hash, buffer, HASH_SIZE) != 0) {
        return 5;  // error outputs[i].lock_script
      }
    }

    /**
     * Check capacity
     **/
    {
      // Load outputs[i].lock_script
      len = BUFFER_SIZE;
      ret = ckb_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_LOCK);
      if (ret != CKB_SUCCESS) {
        return 6; // error load outputs[i].lock_script
      }

      // Get outputs[i].lock_script.args
      mol_seg_t script_seg;
      script_seg.ptr = buffer;
      script_seg.size = len;
      if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
        return 7; // error outputs[i].lock_script
      }
      mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
      if (args_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&args_seg, &script_seg)) {
        return 8; // error outputs[i].lock_script.args
      }
      mol_seg_t raw_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
      if (is_not_seg_tail(&raw_bytes_seg, &args_seg)) {
        return 9; // error outputs[i].lock_script.args
      }

      // Calculate min_input_capacity
      uint64_t min_input_capacity = (8 + 33 + raw_bytes_seg.size) * CKB_UNIT + order_args.price;
      if (min_input_capacity <= order_args.price) {
        return 10;  // price overflow
      }

      // Load inputs[i].capacity
      uint64_t capacity;
      len = 8;
      ret = ckb_load_cell_by_field(
        ((unsigned char *)&capacity), &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY
      );
      if (ret != CKB_SUCCESS || len != 8) {
        return 11;  // error load inputs[i].capacity
      }
      if (capacity < min_input_capacity) {
        return 12;  // error order.price or inputs[i].capacity
      }
      uint64_t diff = capacity - min_input_capacity;

      // Load outputs[i].capacity
      ret = ckb_load_cell_by_field(
        ((unsigned char *)&capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
      );
      if (ret != CKB_SUCCESS || len != 8) {
        return 13;  // error load outputs[i].capacity
      }

      // Load outputs[i].occupied_capacity
      uint64_t occupied_capacity;
      ret = ckb_load_cell_by_field(
        ((unsigned char *)&occupied_capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_OCCUPIED_CAPACITY
      );
      if (ret != CKB_SUCCESS || len != 8) {
        return 14;  // error load outputs[i].occupied_capacity
      }

      // Check capacity
      if (capacity != diff + occupied_capacity + CKB_UNIT) {
        return 15;  // error outputs[i].capacity
      }
    }

    // Load outputs[i].type_script
    len = BUFFER_SIZE;
    ret = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_TYPE);
    if (ret != CKB_SUCCESS) {
      return 16;  // error load outputs[i].type_script
    }

    // Load code_hash and hash_type
    uint8_t* code_hash;
    uint8_t hash_type;
    if (get_code_hash_and_hash_type(buffer, len, &code_hash, &hash_type) != 0) {
      return 17;  // error load code_hash and hash_type
    }

    if (order_args.offer_type == OFFER_COLLECTION) {
      // Check asset_type
      if (order_args.asset_type != 0) {
        return 18;  // Unknown asset_type
      }

      // Check code_hash and hash_type
      int j = 0;
      while (j < ASSET_COUNT) {
        if (
          memcmp(code_hash, ASSET_SCRIPTS[j].code_hash, HASH_SIZE) == 0 &&
          hash_type == ASSET_SCRIPTS[j].hash_type
        ) {
          break;
        }
        j++;
      }
      if (j >= ASSET_COUNT) {
        return 19;  // Unknown asset
      }

      // Load cluster_id
      uint8_t* cluster_id;
      if (load_cluster_id_from_cell_data(buffer, i, &cluster_id) != 0) {
        return 20;  // error load cluster_id
      }

      // Compare cluster_id and order_args.asset_id
      if (memcmp(cluster_id, order_args.asset_id, HASH_SIZE) != 0) {
        return 21;
      }
    } else if (order_args.offer_type == OFFER_ITEM) {
      if (order_args.asset_type >= ASSET_COUNT) {
        return 22;  // Unknown asset type
      }
      // Compare code_hash and hash_type
      if (
        memcmp(code_hash, ASSET_SCRIPTS[order_args.asset_type].code_hash, HASH_SIZE) != 0 ||
        hash_type != ASSET_SCRIPTS[order_args.asset_type].hash_type
      ) {
        return 23;
      }

      // Load asset_id
      mol_seg_t script_seg;
      script_seg.ptr = (uint8_t *)buffer;
      script_seg.size = len;
      mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
      if (args_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&args_seg, &script_seg)) {
        return 24;
      }
      mol_seg_t raw_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
      if (raw_bytes_seg.size != HASH_SIZE || is_not_seg_tail(&raw_bytes_seg, &args_seg)) {
        return 25;
      }

      // Compare asset_id and order_args.asset_id
      if (memcmp(raw_bytes_seg.ptr, order_args.asset_id, HASH_SIZE) != 0) {
        return 26;
      }
    } else {
      return 27;  // Unknown offer_type
    }
  }
  return 0;
}

int main() {
  int ret;
  unsigned char buffer[BUFFER_SIZE];

  // Require: current_script.code_hash == ELEMENT_LOCK_CODE_HASH && current_script.hash_type == 'type'
  ret = check_current_script(buffer);
  if (ret != 0) {
    return 10 + ret;
  }

  // Require: order inputs [0, n - 1] at the front
  //          other inputs [n, total_inputs_len - 1] at the back
  int order_inputs_len;
  ret = check_and_calc_order_inputs_len(buffer, &order_inputs_len);
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
    ret = check_cancel(buffer, order_inputs_len);
    if (ret != 0) {
      return 50 + ret;
    }
  } else {
    // Check signature
    ret = check_signature(buffer, &witness_data);
    if (ret != 0) {
      return 70 + ret;
    }

    if (witness_data.op_code == OP_BUY) {
      // Check buy
      uint16_t fee_rate = witness_data.platform_rate + witness_data.royalty_rate;
      ret = check_buy(buffer, fee_rate, order_inputs_len);
      if (ret != 0) {
        return 80 + ret;
      }
    } else {
      // Check sell
      ret = check_sell(buffer, order_inputs_len);
      if (ret != 0) {
        return 90 + ret;
      }
    }
  }

  // Check gas
  ret = check_gas();
  if (ret != 0) {
    return 120 + ret;
  }
  return 0;
}

/////////////////////////////////////////helper functions////////////////////////////////////////////////////
uint64_t to_uint64(uint8_t* ptr) {
    uint64_t value;
    uint8_t* ptr_value = (uint8_t*)&value;
    for (int i = 0; i < 8; i++) {
        ptr_value[i] = ptr[7 - i];
    }
    return value;
}

bool is_seg_out_of_bounds(const mol_seg_t* inner_seg, const mol_seg_t* outer_seg) {
  if (inner_seg->ptr <= outer_seg->ptr) {
    return true;
  }
  if ((inner_seg->ptr + inner_seg->size) > (outer_seg->ptr + outer_seg->size)) {
    return true;
  }
  return false;
}

bool is_not_seg_tail(const mol_seg_t* inner_seg, const mol_seg_t* outer_seg) {
  return !(inner_seg->ptr > outer_seg->ptr && (inner_seg->ptr + inner_seg->size) == (outer_seg->ptr + outer_seg->size));
}

int get_cancel_args(
  void* buffer,
  blake2b_state* blake2b_ctx_ptr,
  size_t input_index,
  cancel_args_t* args
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
  if (args_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&args_seg, &script_seg)) {
    return 2;
  }
  mol_seg_t raw_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (raw_bytes_seg.size == 0 || is_not_seg_tail(&raw_bytes_seg, &args_seg)) {
    return 3;
  }

  // Read order.side
  mol_seg_t side_seg = mol_table_slice_by_index(&raw_bytes_seg, 0);
  if (side_seg.size != 1 || is_seg_out_of_bounds(&side_seg, &raw_bytes_seg)) {
    return 4;
  }

  // Read order.args
  mol_seg_t args_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 1);
  if (args_bytes_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&args_bytes_seg, &raw_bytes_seg)) {
    return 5;
  }
  mol_seg_t raw_args_bytes_seg = MolReader_Bytes_raw_bytes(&args_bytes_seg);
  if (is_not_seg_tail(&raw_args_bytes_seg, &args_bytes_seg)) {
    return 6;
  }

  // Read order.address
  mol_seg_t address_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 2);
  if (address_bytes_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&address_bytes_seg, &raw_bytes_seg)) {
    return 7;
  }
  mol_seg_t raw_address_bytes_seg = MolReader_Bytes_raw_bytes(&address_bytes_seg);
  if (raw_address_bytes_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&raw_address_bytes_seg, &address_bytes_seg)) {
    return 8;
  }

  // Calc lock hash of address
  blake2b_init(blake2b_ctx_ptr, HASH_SIZE);
  blake2b_update(blake2b_ctx_ptr, raw_address_bytes_seg.ptr, raw_address_bytes_seg.size);
  if (blake2b_final(blake2b_ctx_ptr, args->lock_hash, HASH_SIZE) != 0) {
    return 9;
  }

  // Read order.extra
  mol_seg_t extra_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 3);
  if (extra_bytes_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&extra_bytes_seg, &raw_bytes_seg)) {
    return 10;
  }
  mol_seg_t raw_extra_bytes_seg = MolReader_Bytes_raw_bytes(&extra_bytes_seg);
  if (is_not_seg_tail(&raw_extra_bytes_seg, &extra_bytes_seg)) {
    return 11;
  }

  return 0;
}

int get_listing_args(
  void* buffer,
  blake2b_state* blake2b_ctx_ptr,
  size_t input_index,
  listing_args_t* args
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
  if (args_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&args_seg, &script_seg)) {
    return 2;
  }
  mol_seg_t raw_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (raw_bytes_seg.size == 0 || is_not_seg_tail(&raw_bytes_seg, &args_seg)) {
    return 3;
  }

  // Read order.side
  mol_seg_t side_seg = mol_table_slice_by_index(&raw_bytes_seg, 0);
  if (side_seg.size != 1 || is_seg_out_of_bounds(&side_seg, &raw_bytes_seg)) {
    return 4;
  }
  if (*side_seg.ptr != ORDER_SIDE_LISTING) {
    return 5;
  }

  // Read order.args
  mol_seg_t args_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 1);
  if (args_bytes_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&args_bytes_seg, &raw_bytes_seg)) {
    return 6;
  }
  mol_seg_t raw_args_bytes_seg = MolReader_Bytes_raw_bytes(&args_bytes_seg);
  if (raw_args_bytes_seg.size != 8 || is_not_seg_tail(&raw_args_bytes_seg, &args_bytes_seg)) {
    return 7;
  }
  args->price = to_uint64(raw_args_bytes_seg.ptr);

  // Read order.address
  mol_seg_t address_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 2);
  if (address_bytes_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&address_bytes_seg, &raw_bytes_seg)) {
    return 8;
  }
  mol_seg_t raw_address_bytes_seg = MolReader_Bytes_raw_bytes(&address_bytes_seg);
  if (raw_address_bytes_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&raw_address_bytes_seg, &address_bytes_seg)) {
    return 9;
  }

  // Calc lock hash of address
  blake2b_init(blake2b_ctx_ptr, HASH_SIZE);
  blake2b_update(blake2b_ctx_ptr, raw_address_bytes_seg.ptr, raw_address_bytes_seg.size);
  if (blake2b_final(blake2b_ctx_ptr, args->lock_hash, HASH_SIZE) != 0) {
    return 10;
  }

  // Read order.extra
  mol_seg_t extra_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 3);
  if (extra_bytes_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&extra_bytes_seg, &raw_bytes_seg)) {
    return 11;
  }
  mol_seg_t raw_extra_bytes_seg = MolReader_Bytes_raw_bytes(&extra_bytes_seg);
  if (is_not_seg_tail(&raw_extra_bytes_seg, &extra_bytes_seg)) {
    return 12;
  }
  args->refund_capacity = CAPACITY_DIFFERENCE + (raw_args_bytes_seg.size + raw_extra_bytes_seg.size) * CKB_UNIT;

  return 0;
}

int get_offer_args(
  void* buffer,
  blake2b_state* blake2b_ctx_ptr,
  size_t input_index,
  offer_args_t* args
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
  if (args_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&args_seg, &script_seg)) {
    return 2;
  }
  mol_seg_t raw_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (raw_bytes_seg.size == 0 || is_not_seg_tail(&raw_bytes_seg, &args_seg)) {
    return 3;
  }

  // Read order.side
  mol_seg_t side_seg = mol_table_slice_by_index(&raw_bytes_seg, 0);
  if (side_seg.size != 1 || is_seg_out_of_bounds(&side_seg, &raw_bytes_seg)) {
    return 4;
  }
  if (*side_seg.ptr != ORDER_SIDE_OFFER) {
    return 5;
  }

  // Read order.args
  mol_seg_t args_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 1);
  if (args_bytes_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&args_bytes_seg, &raw_bytes_seg)) {
    return 6;
  }
  mol_seg_t raw_args_bytes_seg = MolReader_Bytes_raw_bytes(&args_bytes_seg);
  if (raw_args_bytes_seg.size != 42 || is_not_seg_tail(&raw_args_bytes_seg, &args_bytes_seg)) {
    return 7;
  }
  args->asset_type = *(raw_args_bytes_seg.ptr);
  args->offer_type = *(raw_args_bytes_seg.ptr + 1);
  args->price = to_uint64(raw_args_bytes_seg.ptr + 2);
  memcpy(args->asset_id, raw_args_bytes_seg.ptr + 10, HASH_SIZE);

  // Read order.address
  mol_seg_t address_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 2);
  if (address_bytes_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&address_bytes_seg, &raw_bytes_seg)) {
    return 8;
  }
  mol_seg_t raw_address_bytes_seg = MolReader_Bytes_raw_bytes(&address_bytes_seg);
  if (raw_address_bytes_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&raw_address_bytes_seg, &address_bytes_seg)) {
    return 9;
  }

  // Calc lock hash of address
  blake2b_init(blake2b_ctx_ptr, HASH_SIZE);
  blake2b_update(blake2b_ctx_ptr, raw_address_bytes_seg.ptr, raw_address_bytes_seg.size);
  if (blake2b_final(blake2b_ctx_ptr, args->lock_hash, HASH_SIZE) != 0) {
    return 10;
  }

  // Read order.extra
  mol_seg_t extra_bytes_seg = mol_table_slice_by_index(&raw_bytes_seg, 3);
  if (extra_bytes_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&extra_bytes_seg, &raw_bytes_seg)) {
    return 11;
  }
  mol_seg_t raw_extra_bytes_seg = MolReader_Bytes_raw_bytes(&extra_bytes_seg);
  if (is_not_seg_tail(&raw_extra_bytes_seg, &extra_bytes_seg)) {
    return 12;
  }

  return 0;
}

int load_cluster_id_from_cell_data(void* buffer, int index, uint8_t** ptr_cluster_id) {
  // Get data.length
  uint64_t len = 0;
  int ret = ckb_load_cell_data((void *)0, &len, 0, index, CKB_SOURCE_OUTPUT);
  if (ret != CKB_SUCCESS || len == 0) {
    return 1;
  }

  // Malloc buffer if needed
  size_t old_len = (size_t)len;
  uint8_t* p_buffer = (len <= BUFFER_SIZE) ? (uint8_t *)buffer : malloc(old_len);
  if (p_buffer == NULL) {
    return 2;
  }

  // Load cell data
  ret = ckb_load_cell_data(p_buffer, &len, 0, index, CKB_SOURCE_OUTPUT);
  if (ret != CKB_SUCCESS || len != old_len) {
    if (p_buffer != buffer) {
      free(p_buffer);
    }
    return 3;
  }

  mol_seg_t data_seg;
  data_seg.ptr = p_buffer;
  data_seg.size = len;

  // Check content type bytes
  mol_seg_t conten_type_seg = mol_table_slice_by_index(&data_seg, 0);
  if (conten_type_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&conten_type_seg, &data_seg)) {
    if (p_buffer != buffer) {
      free(p_buffer);
    }
    return 4;
  }
  mol_seg_t raw_conten_type_seg = MolReader_Bytes_raw_bytes(&conten_type_seg);
  if (is_not_seg_tail(&raw_conten_type_seg, &conten_type_seg)) {
    if (p_buffer != buffer) {
      free(p_buffer);
    }
    return 5;
  }

  // Check content bytes
  mol_seg_t content_seg = mol_table_slice_by_index(&data_seg, 1);
  if (content_seg.size < MOL_NUM_T_SIZE || is_seg_out_of_bounds(&content_seg, &data_seg)) {
    if (p_buffer != buffer) {
      free(p_buffer);
    }
    return 6;
  }
  mol_seg_t raw_content_seg = MolReader_Bytes_raw_bytes(&content_seg);
  if (is_not_seg_tail(&raw_content_seg, &content_seg)) {
    if (p_buffer != buffer) {
      free(p_buffer);
    }
    return 7;
  }

  // Check cluster id bytes
  mol_seg_t cluster_id_seg = mol_table_slice_by_index(&data_seg, 2);
  if (cluster_id_seg.size < MOL_NUM_T_SIZE || is_not_seg_tail(&cluster_id_seg, &data_seg)) {
    if (p_buffer != buffer) {
      free(p_buffer);
    }
    return 8;
  }
  mol_seg_t raw_cluster_id_seg = MolReader_Bytes_raw_bytes(&cluster_id_seg);
  if (raw_cluster_id_seg.size != HASH_SIZE || is_not_seg_tail(&raw_cluster_id_seg, &cluster_id_seg)) {
    if (p_buffer != buffer) {
      free(p_buffer);
    }
    return 9;
  }

  if (p_buffer == buffer) {
    *ptr_cluster_id = raw_cluster_id_seg.ptr;
  } else {
    memcpy(buffer, raw_cluster_id_seg.ptr, HASH_SIZE);
    *ptr_cluster_id = buffer;
    free(p_buffer);
  }
  return 0;
}

int check_gas() {
  int ret;
  uint64_t capacity;

  uint64_t len = 8;
  uint64_t input_capacity = 0;
  for (int i = 0; ; i++) {
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&capacity), &len, 0, i, CKB_SOURCE_INPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret == CKB_SUCCESS && len == 8) {
      input_capacity += capacity;
    } else {
      return 1;
    }
  }

  len = 8;
  uint64_t output_capacity = 0;
  for (int i = 0; ; i++) {
    ret = ckb_load_cell_by_field(
      ((unsigned char *)&capacity), &len, 0, i, CKB_SOURCE_OUTPUT, CKB_CELL_FIELD_CAPACITY
    );
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret == CKB_SUCCESS && len == 8) {
      output_capacity += capacity;
    } else {
      return 2;
    }
  }

  if (input_capacity > output_capacity + MAX_GAS) {
    return 3;
  }
  return 0;
}
