#include "autograph.h"
#include "constants.hpp"
#include "private.hpp"

namespace autograph {

using SecretKey = unsigned char[SECRET_KEY_SIZE];

using Transcript = unsigned char[TRANSCRIPT_SIZE];

HandshakeFunction create_handshake(
    const bool is_initiator, const unsigned char *our_identity_private_key,
    const unsigned char *our_identity_public_key,
    unsigned char *our_ephemeral_private_key,
    const unsigned char *our_ephemeral_public_key) {
  auto perform_handshake = [is_initiator, our_identity_private_key,
                            our_identity_public_key, our_ephemeral_private_key,
                            our_ephemeral_public_key](
                               unsigned char *our_ciphertext,
                               const unsigned char *their_identity_key,
                               const unsigned char *their_ephemeral_key) {
    Transcript transcript;
    SecretKey our_secret_key;
    SecretKey their_secret_key;
    bool success =
        autograph_handshake(transcript, our_ciphertext, our_secret_key,
                            their_secret_key, is_initiator ? 1 : 0,
                            our_identity_private_key, our_identity_public_key,
                            our_ephemeral_private_key, our_ephemeral_public_key,
                            their_identity_key, their_ephemeral_key) == 0;
    SessionFunction establish_session =
        create_session(our_identity_private_key, their_identity_key, transcript,
                       our_secret_key, their_secret_key);
    HandshakeResult result = {success, establish_session};
    return std::move(result);
  };
  return std::move(perform_handshake);
}

}  // namespace autograph
