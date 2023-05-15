#include <stdexcept>
#include <string>

#include "autograph.h"
#include "constants.hpp"
#include "private.hpp"

namespace autograph {

HandshakeFunction create_handshake(const bool is_initiator,
                                   const KeyPair &our_identity_key_pair,
                                   KeyPair &our_ephemeral_key_pair) {
  auto perform_handshake = [is_initiator, our_identity_key_pair,
                            our_ephemeral_key_pair](
                               const ByteVector &their_identity_key,
                               const ByteVector &their_ephemeral_key) {
    ByteVector transcript(TRANSCRIPT_SIZE);
    ByteVector our_secret_key(SECRET_KEY_SIZE);
    ByteVector their_secret_key(SECRET_KEY_SIZE);
    ByteVector our_ciphertext(HANDSHAKE_SIZE);
    bool success =
        autograph_handshake(
            transcript.data(), our_ciphertext.data(), our_secret_key.data(),
            their_secret_key.data(), is_initiator ? 1 : 0,
            our_identity_key_pair.private_key.data(),
            our_identity_key_pair.public_key.data(),
            // TODO: Remove const_cast and figure out this happens in the first
            // place.
            const_cast<unsigned char *>(
                our_ephemeral_key_pair.private_key.data()),
            our_ephemeral_key_pair.public_key.data(), their_identity_key.data(),
            their_ephemeral_key.data()) == 0;
    if (!success) {
      throw std::runtime_error("Handshake failed");
    }
    SessionFunction establish_session =
        create_session(our_identity_key_pair.private_key, their_identity_key,
                       transcript, our_secret_key, their_secret_key);
    Handshake handshake = {our_ciphertext, establish_session};
    return std::move(handshake);
  };
  return std::move(perform_handshake);
}

}  // namespace autograph
