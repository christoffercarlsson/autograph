#include "autograph/create_handshake.h"

#include "autograph/constants.h"
#include "autograph/create_session.h"
#include "autograph/handshake.h"

HandshakeFunction create_handshake(bool is_initiator,
                                   const KeyPair &our_key_pair,
                                   const KeyPair &our_ephemeral_key_pair) {
  auto handshake_function = [is_initiator, &our_key_pair,
                             &our_ephemeral_key_pair](
                                const Chunk &their_identity_key,
                                const Chunk &their_ephemeral_public_key) {
    Chunk transcript(TRANSCRIPT_SIZE);
    Chunk ciphertext(HANDSHAKE_SIZE);
    Chunk our_secret_key(SECRET_KEY_SIZE);
    Chunk their_secret_key(SECRET_KEY_SIZE);
    bool success = handshake(
        transcript.data(), ciphertext.data(), our_secret_key.data(),
        their_secret_key.data(), is_initiator, our_key_pair.private_key.data(),
        our_key_pair.public_key.data(),
        our_ephemeral_key_pair.private_key.data(),
        our_ephemeral_key_pair.public_key.data(), their_identity_key.data(),
        their_ephemeral_public_key.data());
    if (!success) {
      throw std::runtime_error("Failed to perform handshake");
    }
    SessionFunction session =
        create_session(our_key_pair.private_key, their_identity_key, transcript,
                       our_secret_key, their_secret_key);
    Handshake handshake = {ciphertext, session};
    return std::move(handshake);
  };
  return std::move(handshake_function);
}
