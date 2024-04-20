#include "autograph.h"
#include "constants.h"
#include "external.h"

extern "C" {
bool autograph_use_key_pairs(uint8_t *identity_key, uint8_t *session_key,
                             uint8_t *identity_key_pair,
                             uint8_t *session_key_pair,
                             const uint8_t *our_identity_key_pair,
                             uint8_t *our_session_key_pair) {
  autograph_get_public_key(identity_key, our_identity_key_pair);
  autograph_get_public_key(session_key, our_session_key_pair);
  memmove(identity_key_pair, our_identity_key_pair, KEY_PAIR_SIZE);
  memmove(session_key_pair, our_session_key_pair, KEY_PAIR_SIZE);
  zeroize(our_session_key_pair, KEY_PAIR_SIZE);
  return ready();
}

void autograph_use_public_keys(uint8_t *identity_key, uint8_t *session_key,
                               const uint8_t *their_identity_key,
                               const uint8_t *their_session_key) {
  memmove(identity_key, their_identity_key, PUBLIC_KEY_SIZE);
  memmove(session_key, their_session_key, PUBLIC_KEY_SIZE);
}
}

namespace Autograph {

size_t calculateSkippedIndexesSize(
    const optional<uint16_t> skippedIndexesCount) {
  return skippedIndexesCount ? *skippedIndexesCount
                             : DEFAULT_SKIPPED_INDEXES_COUNT;
}

Channel::Channel(const optional<uint16_t> skippedIndexesCount)
    : skippedIndexes(calculateSkippedIndexesSize(skippedIndexesCount)) {
  established = false;
}

bool Channel::isEstablished() const { return established; }

tuple<bool, PublicKey, PublicKey> Channel::useKeyPairs(
    const KeyPair &ourIdentityKeyPair, KeyPair &ourSessionKeyPair) {
  established = false;
  PublicKey identityKey;
  PublicKey sessionKey;
  bool ready = autograph_use_key_pairs(
      identityKey.data(), sessionKey.data(), this->ourIdentityKeyPair.data(),
      this->ourSessionKeyPair.data(), ourIdentityKeyPair.data(),
      ourSessionKeyPair.data());
  return {ready, identityKey, sessionKey};
}

void Channel::usePublicKeys(const PublicKey &theirIdentityKey,
                            const PublicKey &theirSessionKey) {
  established = false;
  autograph_use_public_keys(this->theirIdentityKey.data(),
                            this->theirSessionKey.data(),
                            theirIdentityKey.data(), theirSessionKey.data());
}

tuple<bool, SafetyNumber> Channel::authenticate() const {
  return Autograph::authenticate(ourIdentityKeyPair, theirIdentityKey);
}

tuple<bool, Signature> Channel::certify(const optional<Bytes> &data) const {
  return Autograph::certify(ourIdentityKeyPair, theirIdentityKey, data);
}

bool Channel::verify(const PublicKey &certifierIdentityKey,
                     const Signature &signature,
                     const optional<Bytes> &data) const {
  return Autograph::verify(theirIdentityKey, certifierIdentityKey, signature,
                           data);
}

tuple<bool, Signature> Channel::keyExchange(const bool isInitiator) {
  established = false;
  auto [success, transcript, signature, sendingKey, receivingKey] =
      Autograph::keyExchange(isInitiator, ourIdentityKeyPair, ourSessionKeyPair,
                             theirIdentityKey, theirSessionKey);
  this->transcript = transcript;
  this->sendingKey = sendingKey;
  this->receivingKey = receivingKey;
  return {success, signature};
}

bool Channel::verifyKeyExchange(const Signature &theirSignature) {
  established = Autograph::verifyKeyExchange(transcript, ourIdentityKeyPair,
                                             theirIdentityKey, theirSignature);
  Autograph::zeroize(sendingNonce);
  Autograph::zeroize(receivingNonce);
  skippedIndexes = {0};
  return established;
}

tuple<bool, uint32_t, Bytes> Channel::encrypt(const Bytes &plaintext) {
  auto [success, index, ciphertext] =
      Autograph::encrypt(sendingKey, sendingNonce, plaintext);
  return {established && success, index, ciphertext};
}

tuple<bool, uint32_t, Bytes> Channel::decrypt(const Bytes &ciphertext) {
  auto [success, index, plaintext] = Autograph::decrypt(
      receivingKey, receivingNonce, skippedIndexes, ciphertext);
  return {established && success, index, plaintext};
}

void Channel::close() {
  established = false;
  skippedIndexes = {0};
  Autograph::zeroize(ourIdentityKeyPair);
  Autograph::zeroize(ourSessionKeyPair);
  Autograph::zeroize(sendingKey);
  Autograph::zeroize(receivingKey);
  Autograph::zeroize(sendingNonce);
  Autograph::zeroize(receivingNonce);
}

}  // namespace Autograph
