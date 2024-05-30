add_executable(${AUTOGRAPH_TARGET} ${AUTOGRAPH_SOURCES})

target_compile_options(${AUTOGRAPH_TARGET} PRIVATE -Os)

set(AUTOGRAPH_EXPORTED_FUNCTIONS
    autograph_identity_key_pair
    autograph_session_key_pair
    autograph_authenticate
    autograph_certify
    autograph_verify
    autograph_key_exchange
    autograph_verify_key_exchange
    autograph_encrypt
    autograph_decrypt
    autograph_zeroize
    autograph_is_zero
    autograph_key_pair_size
    autograph_nonce_size
    autograph_public_key_size
    autograph_safety_number_size
    autograph_secret_key_size
    autograph_signature_size
    autograph_transcript_size
    autograph_ciphertext_size
    autograph_plaintext_size
    autograph_use_key_pairs
    autograph_use_public_keys
    calloc
    free)

string(JOIN "\'\,\'_" AUTOGRAPH_EXPORTED_FUNCTIONS
       ${AUTOGRAPH_EXPORTED_FUNCTIONS})
set(AUTOGRAPH_EXPORTED_FUNCTIONS "[\'_${AUTOGRAPH_EXPORTED_FUNCTIONS}\']")

target_link_options(
  ${AUTOGRAPH_TARGET}
  PRIVATE
  -Os
  -sENVIRONMENT=web
  -sEXPORT_ES6=1
  -sEXPORTED_FUNCTIONS=${AUTOGRAPH_EXPORTED_FUNCTIONS}
  -sEXPORTED_RUNTIME_METHODS=ccall
  -sFILESYSTEM=0
  -sMODULARIZE=1
  -sSAFE_HEAP
  -sSINGLE_FILE=1
  -sUSE_ES6_IMPORT_META=0
  -sWASM_BIGINT)
