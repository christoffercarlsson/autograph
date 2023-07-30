#include "handshake.h"

#include "private.h"

namespace autograph {

HandshakeFunction create_handshake(const bool is_initiator,
                                   const SignFunction sign,
                                   const Bytes our_identity_public_key) {
  auto perform_handshake = [is_initiator, sign, our_identity_public_key](
                               KeyPair &our_ephemeral_key_pair,
                               const Bytes their_identity_key,
                               const Bytes their_ephemeral_key) {
    auto safe_sign = create_safe_sign(sign);
    Bytes transcript(128);
    Bytes our_secret_key(32);
    Bytes their_secret_key(32);
    Bytes message(80);
    bool transcript_success =
        autograph_transcript(transcript.data(), is_initiator ? 1 : 0,
                             our_identity_public_key.data(),
                             our_ephemeral_key_pair.public_key.data(),
                             their_identity_key.data(),
                             their_ephemeral_key.data()) == 0;
    auto sign_result = safe_sign(transcript);
    bool handshake_success =
        autograph_handshake_signature(
            message.data(), our_secret_key.data(), their_secret_key.data(),
            is_initiator ? 1 : 0, sign_result.signature.data(),
            our_ephemeral_key_pair.private_key.data(),
            their_ephemeral_key.data()) == 0;
    SessionFunction establish_session =
        create_session(safe_sign, their_identity_key, transcript,
                       our_secret_key, their_secret_key);
    Handshake handshake = {message, establish_session};
    bool success =
        sign_result.success && transcript_success && handshake_success;
    HandshakeResult result = {success, handshake};
    return result;
  };
  return perform_handshake;
}

}  // namespace autograph
