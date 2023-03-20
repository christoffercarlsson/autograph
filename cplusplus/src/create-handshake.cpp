#include "autograph/create-handshake.h"

Chunk get_transcript(bool is_initiator, const KeyPair &our_sign_key_pair,
                     const KeyPair &our_key_pair,
                     const KeyPair &our_ephemeral_key_pair,
                     const Chunk &their_identity,
                     const Chunk &their_ephemeral_public_key) {
  Chunk transcript;
  if (is_initiator) {
    transcript.insert(transcript.end(), our_sign_key_pair.public_key.begin(),
                      our_sign_key_pair.public_key.end());
    transcript.insert(transcript.end(), our_key_pair.public_key.begin(),
                      our_key_pair.public_key.end());
    transcript.insert(transcript.end(), their_identity.begin(),
                      their_identity.end());
    transcript.insert(transcript.end(),
                      our_ephemeral_key_pair.public_key.begin(),
                      our_ephemeral_key_pair.public_key.end());
    transcript.insert(transcript.end(), their_ephemeral_public_key.begin(),
                      their_ephemeral_public_key.end());

  } else {
    transcript.insert(transcript.end(), their_identity.begin(),
                      their_identity.end());
    transcript.insert(transcript.end(), our_sign_key_pair.public_key.begin(),
                      our_sign_key_pair.public_key.end());
    transcript.insert(transcript.end(), our_key_pair.public_key.begin(),
                      our_key_pair.public_key.end());
    transcript.insert(transcript.end(), their_ephemeral_public_key.begin(),
                      their_ephemeral_public_key.end());
    transcript.insert(transcript.end(),
                      our_ephemeral_key_pair.public_key.begin(),
                      our_ephemeral_key_pair.public_key.end());
  }
  return std::move(transcript);
}

HandshakeFunction create_handshake(bool is_initiator,
                                   const KeyPair &our_sign_key_pair,
                                   const KeyPair &our_key_pair,
                                   const KeyPair &our_ephemeral_key_pair) {
  auto handshake_function = [is_initiator, &our_sign_key_pair, &our_key_pair,
                             &our_ephemeral_key_pair](
                                const Chunk &their_identity,
                                const Chunk &their_ephemeral_public_key) {
    Chunk transcript = get_transcript(
        is_initiator, our_sign_key_pair, our_key_pair, our_ephemeral_key_pair,
        their_identity, their_ephemeral_public_key);
    Chunk signature = sign_message(our_sign_key_pair.private_key, transcript);
    SecretKeys secret_keys =
        derive_secret_keys(is_initiator, our_key_pair, our_ephemeral_key_pair,
                           their_identity, their_ephemeral_public_key);
    Chunk ciphertext = encrypt(secret_keys.our_secret_key, 0, signature);
    SessionFunction session =
        create_session(is_initiator, transcript, secret_keys);
    Handshake handshake = {ciphertext, session};
    return std::move(handshake);
  };
  return std::move(handshake_function);
}
