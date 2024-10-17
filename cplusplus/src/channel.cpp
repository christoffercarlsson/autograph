#include "autograph.h"

extern "C" {

void autograph_use_key_pairs(uint8_t *identity_key_pair,
                             uint8_t *session_key_pair,
                             const uint8_t *our_identity_key_pair,
                             const uint8_t *our_session_key_pair) {
  memmove(identity_key_pair, our_identity_key_pair,
          autograph_identity_key_pair_size());
  memmove(session_key_pair, our_session_key_pair,
          autograph_session_key_pair_size());
}

void autograph_use_public_keys(uint8_t *identity_key, uint8_t *session_key,
                               const uint8_t *their_identity_key,
                               const uint8_t *their_session_key) {
  memmove(identity_key, their_identity_key,
          autograph_identity_public_key_size());
  memmove(session_key, their_session_key, autograph_session_public_key_size());
}

}  // extern "C"

namespace Autograph {

Channel::Channel()
    : ourIdentityKeyPair(autograph_identity_key_pair_size()),
      ourSessionKeyPair(autograph_session_key_pair_size()),
      theirIdentityKey(autograph_identity_public_key_size()),
      theirSessionKey(autograph_session_public_key_size()),
      transcript(autograph_transcript_size()),
      sendingKey(autograph_secret_key_size()),
      receivingKey(autograph_secret_key_size()),
      sendingNonce(createNonce()),
      receivingNonce(createNonce()),
      skippedIndexes(createSkippedIndexes(std::nullopt)) {}

std::tuple<Bytes, Bytes> Channel::useKeyPairs(const Bytes &ourIdentityKeyPair,
                                              const Bytes &ourSessionKeyPair) {
  autograph_use_key_pairs(this->ourIdentityKeyPair.data(),
                          this->ourSessionKeyPair.data(),
                          ourIdentityKeyPair.data(), ourSessionKeyPair.data());
  return Autograph::getPublicKeys(ourIdentityKeyPair, ourSessionKeyPair);
}

void Channel::usePublicKeys(const Bytes &theirIdentityKey,
                            const Bytes &theirSessionKey) {
  autograph_use_public_keys(this->theirIdentityKey.data(),
                            this->theirSessionKey.data(),
                            theirIdentityKey.data(), theirSessionKey.data());
}

std::tuple<bool, Bytes> Channel::authenticate(const Bytes &ourId,
                                              const Bytes &theirId) const {
  return Autograph::authenticate(ourIdentityKeyPair, ourId, theirIdentityKey,
                                 theirId);
}

std::tuple<bool, Bytes> Channel::certify(
    const std::optional<Bytes> &data) const {
  return Autograph::certify(ourIdentityKeyPair, theirIdentityKey, data);
}

bool Channel::verify(const Bytes &certifierIdentityKey, const Bytes &signature,
                     const std::optional<Bytes> &data) const {
  return Autograph::verify(theirIdentityKey, certifierIdentityKey, signature,
                           data);
}

std::tuple<bool, Bytes> Channel::keyExchange(const bool isInitiator) {
  auto [success, transcript, signature, sendingKey, receivingKey] =
      Autograph::keyExchange(isInitiator, ourIdentityKeyPair, ourSessionKeyPair,
                             theirIdentityKey, theirSessionKey);
  this->transcript = transcript;
  this->sendingKey = sendingKey;
  this->receivingKey = receivingKey;
  return {success, signature};
}

bool Channel::verifyKeyExchange(const Bytes &theirSignature) {
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
