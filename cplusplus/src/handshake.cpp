#include "autograph/handshake.h"

#include "autograph/core/handshake.h"
#include "autograph/session.h"

namespace autograph {

using SecretKey = unsigned char[autograph_crypto_kdf_KEY_SIZE];

using Transcript = unsigned char[autograph_core_handshake_TRANSCRIPT_SIZE];

HandshakeFunction create_handshake(
    bool is_initiator, const unsigned char* our_identity_private_key,
    const unsigned char* our_identity_public_key,
    const unsigned char* our_ephemeral_private_key,
    const unsigned char* our_ephemeral_public_key) {
  auto perform_handshake = [is_initiator, our_identity_private_key,
                            our_identity_public_key, our_ephemeral_private_key,
                            our_ephemeral_public_key](
                               unsigned char* our_ciphertext,
                               const unsigned char* their_identity_key,
                               const unsigned char* their_ephemeral_key) {
    Transcript transcript;
    SecretKey our_secret_key;
    SecretKey their_secret_key;
    int result = autograph_core_handshake(
        transcript, our_ciphertext, our_secret_key, their_secret_key,
        is_initiator ? 1 : 0, our_identity_private_key, our_identity_public_key,
        our_ephemeral_private_key, our_ephemeral_public_key, their_identity_key,
        their_ephemeral_key);
    if (result != 0) {
      throw std::runtime_error("Failed to perform handshake");
    }
    SessionFunction establish_session =
        create_session(our_identity_private_key, their_identity_key, transcript,
                       our_secret_key, their_secret_key);
    return std::move(establish_session);
  };
  return std::move(perform_handshake);
}

}  // namespace autograph
