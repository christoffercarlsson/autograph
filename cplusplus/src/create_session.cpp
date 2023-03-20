#include "autograph/create_session.h"

SessionFunction create_session(const Chunk &our_private_key,
                               const Chunk &their_identity_key,
                               const Chunk &transcript,
                               const SecretKeys &secret_keys) {
  auto session_function = [&our_private_key, &their_identity_key, &transcript,
                           &secret_keys](const Chunk &ciphertext) {
    bool verified = verify_transcript(transcript, their_identity_key,
                                      secret_keys.their_secret_key, ciphertext);
    if (!verified) {
      throw std::runtime_error("Handshake verification failed");
    }
    auto certify = create_certify(our_private_key, their_identity_key);
    auto decrypt = create_decrypt(secret_keys.their_secret_key);
    auto encrypt = create_encrypt(secret_keys.our_secret_key);
    auto verify = create_verify(their_identity_key, decrypt);
    Session session = {certify, decrypt, encrypt, verify};
    return std::move(session);
  };
  return std::move(session_function);
}
