#include "autograph/handshake.h"

#include "autograph/core/handshake.h"
#include "autograph/crypto/kdf.h"
#include "autograph/session.h"

namespace autograph {

HandshakeFunction create_handshake(bool is_initiator,
                                   const KeyPair &our_key_pair,
                                   const Chunk &our_ephemeral_private_key,
                                   const Chunk &our_ephemeral_public_key) {
  auto perform_handshake =
      [is_initiator, &our_key_pair, &our_ephemeral_private_key,
       &our_ephemeral_public_key](const Chunk &their_identity_key,
                                  const Chunk &their_ephemeral_public_key) {
        Chunk transcript(autograph_core_handshake_TRANSCRIPT_SIZE);
        Chunk ciphertext(autograph_core_handshake_SIZE);
        Chunk our_secret_key(autograph_crypto_kdf_KEY_SIZE);
        Chunk their_secret_key(autograph_crypto_kdf_KEY_SIZE);
        int result = autograph_core_handshake(
            transcript.data(), ciphertext.data(), our_secret_key.data(),
            their_secret_key.data(), is_initiator ? 1 : 0,
            our_key_pair.private_key.data(), our_key_pair.public_key.data(),
            our_ephemeral_private_key.data(), our_ephemeral_public_key.data(),
            their_identity_key.data(), their_ephemeral_public_key.data());
        if (result != 0) {
          throw std::runtime_error("Failed to perform handshake");
        }
        SessionFunction establish_session =
            create_session(our_key_pair.private_key, their_identity_key,
                           transcript, our_secret_key, their_secret_key);
        Handshake handshake = {ciphertext, establish_session};
        return std::move(handshake);
      };
  return std::move(perform_handshake);
}

}  // namespace autograph
