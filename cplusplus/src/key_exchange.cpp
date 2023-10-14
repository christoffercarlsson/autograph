#include "key_exchange.h"

#include "private.h"

namespace Autograph {

KeyExchangeVerificationFunction createKeyExchangeVerification(
    const SignFunction sign, const Bytes theirPublicKey, const Bytes transcript,
    Bytes ourSecretKey, Bytes theirSecretKey) {
  auto verify = [sign, theirPublicKey, transcript, ourSecretKey,
                 theirSecretKey](const Bytes theirMessage) mutable {
    bool success = autograph_key_exchange_verify(
                       transcript.data(), theirPublicKey.data(),
                       theirSecretKey.data(), theirMessage.data()) == 0;
    auto decrypt = createDecrypt(theirSecretKey);
    auto encrypt = createEncrypt(ourSecretKey);
    auto signData = createSignData(sign, theirPublicKey);
    auto signIdentity = createSignIdentity(sign, theirPublicKey);
    auto verifyData = createVerifyData(theirPublicKey);
    auto verifyIdentity = createVerifyIdentity(theirPublicKey);
    Session session = {decrypt,      encrypt,    signData,
                       signIdentity, verifyData, verifyIdentity};
    KeyExchangeVerificationResult result = {success, session};
    return result;
  };
  return verify;
}

KeyExchangeFunction createKeyExchange(const bool isInitiator,
                                      const SignFunction sign,
                                      const Bytes ourIdentityPublicKey) {
  auto performKeyExchange = [isInitiator, sign, ourIdentityPublicKey](
                                KeyPair &ourEphemeralKeyPair,
                                const Bytes theirIdentityKey,
                                const Bytes theirEphemeralKey) {
    auto safeSign = createSafeSign(sign);
    Bytes transcript(128);
    Bytes ourSecretKey(32);
    Bytes theirSecretKey(32);
    Bytes handshake(96);
    bool transcriptSuccess =
        autograph_key_exchange_transcript(
            transcript.data(), isInitiator ? 1 : 0, ourIdentityPublicKey.data(),
            ourEphemeralKeyPair.publicKey.data(), theirIdentityKey.data(),
            theirEphemeralKey.data()) == 0;
    auto signResult = safeSign(transcript);
    bool keyExchangeSuccess =
        autograph_key_exchange_signature(
            handshake.data(), ourSecretKey.data(), theirSecretKey.data(),
            isInitiator ? 1 : 0, signResult.signature.data(),
            ourEphemeralKeyPair.privateKey.data(),
            theirEphemeralKey.data()) == 0;
    KeyExchangeVerificationFunction verify = createKeyExchangeVerification(
        safeSign, theirIdentityKey, transcript, ourSecretKey, theirSecretKey);
    KeyExchange keyExchange = {handshake, verify};
    bool success =
        signResult.success && transcriptSuccess && keyExchangeSuccess;
    KeyExchangeResult result = {success, keyExchange};
    return result;
  };
  return performKeyExchange;
}

}  // namespace Autograph
