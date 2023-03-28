#include "autograph/verify_session.h"

#include "autograph/aes.h"
#include "autograph/constants.h"
#include "autograph/verify_signature.h"
#include "sodium.h"

bool verify_session(const unsigned char *transcript,
                    const unsigned char *their_identity_key,
                    const unsigned char *their_secret_key,
                    const unsigned char *ciphertext) {
  unsigned char signature[SIGNATURE_SIZE];
  bool decrypt_result =
      aes_decrypt(signature, their_secret_key, 0, ciphertext,
                  SIGNATURE_SIZE + crypto_aead_aes256gcm_ABYTES);
  if (!decrypt_result) {
    return false;
  }
  return verify_signature(their_identity_key, transcript, TRANSCRIPT_SIZE,
                          signature);
}
