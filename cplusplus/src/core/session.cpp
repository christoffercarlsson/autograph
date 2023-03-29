#include "autograph/core/session.h"

#include "autograph/core/handshake.h"
#include "autograph/crypto/aes.h"
#include "autograph/crypto/sign.h"

int autograph_core_session(const unsigned char *transcript,
                           const unsigned char *their_identity_key,
                           const unsigned char *their_secret_key,
                           const unsigned char *ciphertext) {
  unsigned char signature[autograph_crypto_sign_SIGNATURE_SIZE];
  bool decrypt_result =
      autograph_crypto_aes_decrypt(signature, their_secret_key, 0, ciphertext,
                                   autograph_core_handshake_SIZE);
  if (!decrypt_result) {
    return -1;
  }
  bool verified = autograph_crypto_sign_verify(
      their_identity_key, transcript, autograph_core_handshake_TRANSCRIPT_SIZE,
      signature);
  return verified ? 0 : -1;
}
