#include <vector>

#include "autograph.h"
#include "constants.hpp"
#include "crypto.hpp"

int autograph_session(const unsigned char *transcript,
                      const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *ciphertext) {
  std::vector<unsigned char> signature(autograph::SIGNATURE_SIZE);
  bool decrypt_result =
      autograph::decrypt(signature.data(), their_secret_key, 0, ciphertext,
                         autograph::HANDSHAKE_SIZE);
  if (!decrypt_result) {
    return -1;
  }
  return autograph::verify(their_identity_key, transcript,
                           autograph::TRANSCRIPT_SIZE, signature.data())
             ? 0
             : -1;
}
