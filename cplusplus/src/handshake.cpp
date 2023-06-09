#include <stdexcept>
#include <string>

#include "internal.h"

namespace autograph {

HandshakeFunction create_handshake(const bool is_initiator,
                                   const KeyPair &our_identity_key_pair,
                                   KeyPair &our_ephemeral_key_pair) {
  auto perform_handshake =
      [is_initiator, &our_identity_key_pair, &our_ephemeral_key_pair](
          const Bytes &their_identity_key, const Bytes &their_ephemeral_key) {
        Bytes transcript(128);
        Bytes our_secret_key(32);
        Bytes their_secret_key(32);
        Bytes message(80);
        bool success =
            autograph_handshake(
                transcript.data(), message.data(), our_secret_key.data(),
                their_secret_key.data(), is_initiator ? 1 : 0,
                our_identity_key_pair.private_key.data(),
                our_identity_key_pair.public_key.data(),
                our_ephemeral_key_pair.private_key.data(),
                our_ephemeral_key_pair.public_key.data(),
                their_identity_key.data(), their_ephemeral_key.data()) == 0;
        if (!success) {
          throw std::runtime_error("Handshake failed");
        }
        SessionFunction establish_session = create_session(
            our_identity_key_pair.private_key, their_identity_key, transcript,
            our_secret_key, their_secret_key);
        Handshake handshake = {message, establish_session};
        return std::move(handshake);
      };
  return std::move(perform_handshake);
}

}  // namespace autograph
