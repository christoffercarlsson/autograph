#include "autograph/create_handshake.h"

#include "autograph/create_session.h"
#include "autograph/derive_secret_keys.h"
#include "autograph/encrypt.h"
#include "autograph/get_transcript.h"
#include "autograph/sign_message.h"

HandshakeFunction create_handshake(bool is_initiator,
                                   const KeyPair &our_key_pair,
                                   const KeyPair &our_ephemeral_key_pair) {
  auto handshake_function = [is_initiator, &our_key_pair,
                             &our_ephemeral_key_pair](
                                const Chunk &their_identity_key,
                                const Chunk &their_ephemeral_public_key) {
    Chunk transcript =
        get_transcript(is_initiator, our_key_pair, our_ephemeral_key_pair,
                       their_identity_key, their_ephemeral_public_key);
    Chunk signature = sign_message(our_key_pair.private_key, transcript);
    SecretKeys secret_keys = derive_secret_keys(
        is_initiator, our_ephemeral_key_pair, their_ephemeral_public_key);
    Chunk ciphertext = encrypt(secret_keys.our_secret_key, 0, signature);
    SessionFunction session = create_session(
        our_key_pair.private_key, their_identity_key, transcript, secret_keys);
    Handshake handshake = {ciphertext, session};
    return std::move(handshake);
  };
  return std::move(handshake_function);
}
