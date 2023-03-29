#include "autograph/core/handshake.h"

#include <vector>

#include "autograph/core/key_pair.h"
#include "autograph/crypto/aes.h"
#include "autograph/crypto/diffie_hellman.h"
#include "autograph/crypto/kdf.h"
#include "autograph/crypto/sign.h"
#include "sodium.h"

void autograph_core_handshake_transcript(
    unsigned char *transcript, bool is_initiator,
    const unsigned char *our_identity_key,
    const unsigned char *our_ephemeral_key,
    const unsigned char *their_identity_key,
    const unsigned char *their_ephemeral_key) {
  auto result =
      std::vector<unsigned char>(autograph_core_handshake_TRANSCRIPT_SIZE);
  if (is_initiator) {
    result.insert(result.end(), our_identity_key,
                  our_identity_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
    result.insert(result.end(), their_identity_key,
                  their_identity_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
    result.insert(result.end(), our_ephemeral_key,
                  our_ephemeral_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
    result.insert(
        result.end(), their_ephemeral_key,
        their_ephemeral_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
  } else {
    result.insert(result.end(), their_identity_key,
                  their_identity_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
    result.insert(result.end(), our_identity_key,
                  our_identity_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
    result.insert(
        result.end(), their_ephemeral_key,
        their_ephemeral_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
    result.insert(result.end(), our_ephemeral_key,
                  our_ephemeral_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
  }
  std::move(result.begin(), result.end(), transcript);
}

bool autograph_core_handshake_ciphertext(unsigned char *ciphertext,
                                         const unsigned char *transcript,
                                         const unsigned char *our_private_key,
                                         const unsigned char *our_secret_key) {
  unsigned char signature[autograph_crypto_sign_SIGNATURE_SIZE];
  bool signature_result =
      autograph_crypto_sign(signature, our_private_key, transcript,
                            autograph_core_handshake_TRANSCRIPT_SIZE);
  if (!signature_result) {
    return false;
  }
  return autograph_crypto_aes_encrypt(ciphertext, our_secret_key, 0, signature,
                                      autograph_crypto_sign_SIGNATURE_SIZE);
}

bool autograph_core_handshake_keys(unsigned char *our_secret_key,
                                   unsigned char *their_secret_key,
                                   bool is_initiator,
                                   unsigned char *our_private_key,
                                   const unsigned char *their_public_key) {
  unsigned char ikm[autograph_crypto_diffie_hellman_OUTPUT_SIZE];
  bool dh_result =
      autograph_crypto_diffie_hellman(ikm, our_private_key, their_public_key);
  bool our_key_result = autograph_crypto_kdf(
      our_secret_key, ikm,
      is_initiator ? autograph_core_handshake_CONTEXT_INITIATOR
                   : autograph_core_handshake_CONTEXT_RESPONDER);
  bool their_key_result = autograph_crypto_kdf(
      their_secret_key, ikm,
      is_initiator ? autograph_core_handshake_CONTEXT_RESPONDER
                   : autograph_core_handshake_CONTEXT_INITIATOR);
  sodium_memzero(our_private_key, autograph_core_key_pair_PRIVATE_KEY_SIZE);
  sodium_memzero(ikm, autograph_crypto_diffie_hellman_OUTPUT_SIZE);
  return dh_result && our_key_result && their_key_result;
}

int autograph_core_handshake(unsigned char *transcript,
                             unsigned char *ciphertext,
                             unsigned char *our_secret_key,
                             unsigned char *their_secret_key,
                             const unsigned int is_initiator,
                             const unsigned char *our_private_identity_key,
                             const unsigned char *our_public_identity_key,
                             unsigned char *our_private_ephemeral_key,
                             const unsigned char *our_public_ephemeral_key,
                             const unsigned char *their_public_identity_key,
                             const unsigned char *their_public_ephemeral_key) {
  bool initiator = is_initiator == 1;
  autograph_core_handshake_transcript(
      transcript, initiator, our_public_identity_key, our_public_ephemeral_key,
      their_public_identity_key, their_public_ephemeral_key);
  bool derive_result = autograph_core_handshake_keys(
      our_secret_key, their_secret_key, initiator, our_private_ephemeral_key,
      their_public_ephemeral_key);
  if (!derive_result) {
    return -1;
  }
  bool ciphertext_result = autograph_core_handshake_ciphertext(
      ciphertext, transcript, our_private_identity_key,
      our_private_ephemeral_key);
  if (!ciphertext_result) {
    return -1;
  }
  return 0;
}
