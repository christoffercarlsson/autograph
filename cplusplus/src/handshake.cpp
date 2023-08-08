#include "handshake.h"

#include "private.h"

namespace Autograph {

HandshakeFunction createHandshake(const bool isInitiator,
                                  const SignFunction sign,
                                  const Bytes ourIdentityPublicKey) {
  auto perform_handshake = [isInitiator, sign, ourIdentityPublicKey](
                               KeyPair &ourEphemeralKeyPair,
                               const Bytes theirIdentityKey,
                               const Bytes theirEphemeralKey) {
    auto safeSign = createSafeSign(sign);
    Bytes transcript(128);
    Bytes ourSecretKey(32);
    Bytes theirSecretKey(32);
    Bytes message(80);
    bool transcriptSuccess =
        autograph_transcript(
            transcript.data(), isInitiator ? 1 : 0, ourIdentityPublicKey.data(),
            ourEphemeralKeyPair.publicKey.data(), theirIdentityKey.data(),
            theirEphemeralKey.data()) == 0;
    auto signResult = safeSign(transcript);
    bool handshakeSuccess =
        autograph_handshake_signature(
            message.data(), ourSecretKey.data(), theirSecretKey.data(),
            isInitiator ? 1 : 0, signResult.signature.data(),
            ourEphemeralKeyPair.privateKey.data(),
            theirEphemeralKey.data()) == 0;
    SessionFunction establish_session = createSession(
        safeSign, theirIdentityKey, transcript, ourSecretKey, theirSecretKey);
    Handshake handshake = {message, establish_session};
    bool success = signResult.success && transcriptSuccess && handshakeSuccess;
    HandshakeResult result = {success, handshake};
    return result;
  };
  return perform_handshake;
}

}  // namespace Autograph
