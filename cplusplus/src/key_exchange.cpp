#include "autograph.h"

namespace Autograph {

tuple<bool, Transcript, Signature, SecretKey, SecretKey> keyExchange(
    const bool isInitiator, const KeyPair &ourIdentityKeyPair,
    KeyPair &ourSessionKeyPair, const PublicKey &theirIdentityKey,
    const PublicKey &theirSessionKey) {
  Transcript transcript;
  Signature ourSignature;
  SecretKey sendingKey;
  SecretKey receivingKey;
  bool success = autograph_key_exchange(
      transcript.data(), ourSignature.data(), sendingKey.data(),
      receivingKey.data(), isInitiator, ourIdentityKeyPair.data(),
      ourSessionKeyPair.data(), theirIdentityKey.data(),
      theirSessionKey.data());
  return {success, transcript, ourSignature, sendingKey, receivingKey};
}

bool verifyKeyExchange(const Transcript &transcript,
                       const KeyPair &ourIdentityKeyPair,
                       const PublicKey &theirIdentityKey,
                       const Signature &theirSignature) {
  return autograph_verify_key_exchange(
      transcript.data(), ourIdentityKeyPair.data(), theirIdentityKey.data(),
      theirSignature.data());
}

}  // namespace Autograph
