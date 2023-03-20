#include "autograph/verify_transcript.h"

bool verify_transcript(const Chunk &transcript, const Chunk &their_identity_key,
                       const Chunk &their_secret_key, const Chunk &ciphertext) {
  try {
    Chunk signature = decrypt(their_secret_key, 0, ciphertext);
    bool verified = verify_signature(their_identity_key, transcript, signature);
    return verified;
  } catch (std::exception &error) {
    return false;
  }
}
