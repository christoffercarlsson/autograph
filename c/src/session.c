#include "autograph.h"
#include "crypto.h"

int autograph_session(const unsigned char *transcript,
                      const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *ciphertext) {
  unsigned char signature[64];
  int decrypt_result = decrypt(signature, their_secret_key, 0, ciphertext, 80);
  if (decrypt_result != 0) {
    return -1;
  }
  return verify(their_identity_key, transcript, 128, signature) == 0 ? 0 : -1;
}
