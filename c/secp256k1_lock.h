#ifndef CKB_LOCK_UTILS_H_
#define CKB_LOCK_UTILS_H_

#define HASH_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define RECID_INDEX 64

#define BUFFER_SIZE 32768
#define SIGNATURE_SIZE 65


int validate_signature(
  uint8_t pubkey_hash[BLAKE160_SIZE],
  uint8_t message_hash[HASH_SIZE],
  uint8_t signature_bytes[SIGNATURE_SIZE]
) {
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  if (ckb_secp256k1_custom_verify_only_initialize(&context, secp_data) != 0) {
    return 1;  // error secp256k1 initialize
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (
    secp256k1_ecdsa_recoverable_signature_parse_compact(
      &context, 
      &signature, 
      signature_bytes, 
      signature_bytes[RECID_INDEX]
    ) == 0
  ) {
    return 2;  // error parse signature
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message_hash) != 1) {
    return 3;  // error recover pubkey
  }

  /* Serialize pubkey */
  size_t pubkey_size = PUBKEY_SIZE;
  uint8_t output_pubkey[PUBKEY_SIZE];
  if (
    secp256k1_ec_pubkey_serialize(
      &context, 
      output_pubkey, 
      &pubkey_size, 
      &pubkey, 
      SECP256K1_EC_COMPRESSED
    ) != 1
  ) {
    return 4;  // error serialize pubkey
  }

  // As mentioned above, we are only using the first 160 bits(20 bytes), if they match
  // the value provided as the first 20 bytes of script args, the signature verification
  // is considered to be successful.
  if (memcmp(pubkey_hash, output_pubkey, BLAKE160_SIZE) != 0) {
    return 5;  // error pubkey hash
  }
  return 0;
}

#endif /* CKB_LOCK_UTILS_H_ */
