#include "autograph.h"
#include "constants.h"

extern "C" {

void autograph_use_key_pairs(uint8_t *identity_key_pair,
                             uint8_t *session_key_pair,
                             const uint8_t *our_identity_key_pair,
                             const uint8_t *our_session_key_pair) {
  memmove(identity_key_pair, our_identity_key_pair, KEY_PAIR_SIZE);
  memmove(session_key_pair, our_session_key_pair, KEY_PAIR_SIZE);
}

void autograph_use_public_keys(uint8_t *identity_key, uint8_t *session_key,
                               const uint8_t *their_identity_key,
                               const uint8_t *their_session_key) {
  memmove(identity_key, their_identity_key, PUBLIC_KEY_SIZE);
  memmove(session_key, their_session_key, PUBLIC_KEY_SIZE);
}

}  // extern "C"

namespace Autograph {

Channel::Channel(const KeyPair &ourIdentityKeyPair,
                 const KeyPair &ourSessionKeyPair,
                 const PublicKey &theirIdentityKey,
                 const PublicKey &theirSessionKey) {
  autograph_use_key_pairs(this->ourIdentityKeyPair.data(),
                          this->ourSessionKeyPair.data(),
                          ourIdentityKeyPair.data(), ourSessionKeyPair.data());
  autograph_use_public_keys(this->theirIdentityKey.data(),
                            this->theirSessionKey.data(),
                            theirIdentityKey.data(), theirSessionKey.data());
  sendingNonce.fill(0);
  receivingNonce.fill(0);
  skippedIndexes.fill(0);
}

std::tuple<bool, SafetyNumber> Channel::authenticate() const {
  return Autograph::authenticate(ourIdentityKeyPair, theirIdentityKey);
}

std::tuple<bool, Signature> Channel::certify(
    const std::optional<Bytes> &data) const {
  return Autograph::certify(ourIdentityKeyPair, theirIdentityKey, data);
}

bool Channel::verify(const PublicKey &certifierIdentityKey,
                     const Signature &signature,
                     const std::optional<Bytes> &data) const {
  return Autograph::verify(theirIdentityKey, certifierIdentityKey, signature,
                           data);
}

std::tuple<bool, Signature> Channel::keyExchange(const bool isInitiator) {
  auto [success, transcript, signature, sendingKey, receivingKey] =
      Autograph::keyExchange(isInitiator, ourIdentityKeyPair, ourSessionKeyPair,
                             theirIdentityKey, theirSessionKey);
  this->transcript = transcript;
  this->sendingKey = sendingKey;
  this->receivingKey = receivingKey;
  return {success, signature};
}

bool Channel::verifyKeyExchange(const Signature &theirSignature) {
  return Autograph::verifyKeyExchange(transcript, ourIdentityKeyPair,
                                      theirIdentityKey, theirSignature);
}

std::tuple<bool, uint32_t, Bytes> Channel::encrypt(const Bytes &plaintext) {
  return Autograph::encrypt(sendingKey, sendingNonce, plaintext);
}

std::tuple<bool, uint32_t, Bytes> Channel::decrypt(const Bytes &ciphertext) {
  return Autograph::decrypt(receivingKey, receivingNonce, skippedIndexes,
                            ciphertext);
}

}  // namespace Autograph
