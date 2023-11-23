#include "channel.h"

#include <vector>

#include "error.h"
#include "init.h"
#include "safety_number.h"
#include "sizes.h"

namespace Autograph {

DecryptionState::DecryptionState(std::vector<unsigned char> secretKey)
    : messageIndex(INDEX_SIZE),
      decryptIndex(INDEX_SIZE),
      plaintextSize(SIZE_SIZE),
      secretKey(std::move(secretKey)),
      skippedKeys(SKIPPED_KEYS_SIZE) {}

unsigned long long DecryptionState::readMessageIndex() const {
  return autograph_read_uint64(messageIndex.data());
}

unsigned int DecryptionState::readPlaintextSize() const {
  return autograph_read_uint32(plaintextSize.data());
}

void DecryptionState::resizeData(std::vector<unsigned char> &plaintext) const {
  plaintext.resize(readPlaintextSize());
}

EncryptionState::EncryptionState(std::vector<unsigned char> secretKey)
    : messageIndex(INDEX_SIZE), secretKey(std::move(secretKey)) {}

unsigned long long EncryptionState::readMessageIndex() const {
  return autograph_read_uint64(messageIndex.data());
}

unsigned int getCiphertextSize(unsigned int plaintextSize) {
  return autograph_ciphertext_size(plaintextSize);
}

unsigned int getPlaintextSize(unsigned int ciphertextSize) {
  return autograph_plaintext_size(ciphertextSize);
}

unsigned int getSubjectSize(unsigned int size) {
  return autograph_subject_size(size);
}

size_t countCertificates(const std::vector<unsigned char> &certificates) {
  return certificates.size() / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE);
}

std::vector<unsigned char> getSafetyNumber(std::vector<unsigned char> a,
                                           std::vector<unsigned char> b) {
  return calculateSafetyNumber(a, b);
}

Channel::Channel(const SignFunction sign,
                 const std::vector<unsigned char> ourIdentityKey)
    : sign(sign),
      ourIdentityKey(ourIdentityKey),
      decryptState(std::nullopt),
      encryptState(std::nullopt),
      theirPublicKey(std::nullopt),
      transcript(std::nullopt),
      verified(false) {
  if (autograph_init() != 0) {
    throw Error(Error::Initialization);
  }
}

std::vector<unsigned char> Channel::calculateSafetyNumber() const {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  return getSafetyNumber(ourIdentityKey, theirPublicKey.value());
}

void Channel::close() {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  decryptState.reset();
  encryptState.reset();
  theirPublicKey.reset();
  transcript.reset();
  verified = false;
}

std::tuple<unsigned long long, std::vector<unsigned char>> Channel::decrypt(
    const std::vector<unsigned char> message) {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  std::vector<unsigned char> plaintext(getPlaintextSize(message.size()));
  DecryptionState &state = decryptState.value();
  bool success =
      autograph_decrypt(plaintext.data(), state.plaintextSize.data(),
                        state.messageIndex.data(), state.decryptIndex.data(),
                        state.skippedKeys.data(), state.secretKey.data(),
                        message.data(), message.size()) == 0;
  if (!success) {
    throw Error(Error::Decryption);
  }
  state.resizeData(plaintext);
  return std::make_tuple(state.readMessageIndex(), plaintext);
}

std::tuple<unsigned long long, std::vector<unsigned char>> Channel::encrypt(
    const std::vector<unsigned char> &plaintext) {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  std::vector<unsigned char> ciphertext(getCiphertextSize(plaintext.size()));
  EncryptionState &state = encryptState.value();
  bool success = autograph_encrypt(ciphertext.data(), state.messageIndex.data(),
                                   state.secretKey.data(), plaintext.data(),
                                   plaintext.size()) == 0;
  if (!success) {
    throw Error(Error::Encryption);
  }
  return std::make_tuple(state.readMessageIndex(), ciphertext);
}

bool Channel::isClosed() const { return !(isEstablished() || isInitialized()); }

bool Channel::isEstablished() const {
  return theirPublicKey.has_value() && decryptState.has_value() &&
         encryptState.has_value() && !transcript.has_value() &&
         verified == true;
}

bool Channel::isInitialized() const {
  return theirPublicKey.has_value() && decryptState.has_value() &&
         encryptState.has_value() && transcript.has_value() &&
         verified == false;
}

std::vector<unsigned char> Channel::performKeyExchange(
    const bool isInitiator, KeyPair &ourEphemeralKeyPair,
    const std::vector<unsigned char> theirIdentityKey,
    const std::vector<unsigned char> theirEphemeralKey) {
  if (isEstablished()) {
    throw Error(Error::ChannelAlreadyEstablished);
  }
  if (isInitialized()) {
    throw Error(Error::ChannelAlreadyInitialized);
  }
  std::vector<unsigned char> ourTranscript(TRANSCRIPT_SIZE);
  std::vector<unsigned char> ourSecretKey(SECRET_KEY_SIZE);
  std::vector<unsigned char> theirSecretKey(SECRET_KEY_SIZE);
  std::vector<unsigned char> handshake(HANDSHAKE_SIZE);
  bool transcriptSuccess =
      autograph_key_exchange_transcript(
          ourTranscript.data(), isInitiator ? 1 : 0, ourIdentityKey.data(),
          ourEphemeralKeyPair.publicKey.data(), theirIdentityKey.data(),
          theirEphemeralKey.data()) == 0;
  auto signature = sign(ourTranscript);
  bool keyExchangeSuccess =
      autograph_key_exchange_signature(
          handshake.data(), ourSecretKey.data(), theirSecretKey.data(),
          isInitiator ? 1 : 0, signature.data(),
          ourEphemeralKeyPair.privateKey.data(), theirEphemeralKey.data()) == 0;
  if (!keyExchangeSuccess) {
    throw Error(Error::KeyExchange);
  }
  decryptState = DecryptionState(theirSecretKey);
  encryptState = EncryptionState(ourSecretKey);
  theirPublicKey = theirIdentityKey;
  transcript = ourTranscript;
  verified = false;
  return handshake;
}

std::vector<unsigned char> Channel::signData(
    const std::vector<unsigned char> &data) const {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  std::vector<unsigned char> subject(getSubjectSize(data.size()));
  autograph_subject(subject.data(), theirPublicKey.value().data(), data.data(),
                    data.size());
  auto signature = sign(subject);
  return signature;
}

std::vector<unsigned char> Channel::signIdentity() const {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  auto signature = sign(theirPublicKey.value());
  return signature;
}

bool Channel::verifyData(const std::vector<unsigned char> &certificates,
                         const std::vector<unsigned char> &data) const {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  return autograph_verify_data(
             theirPublicKey.value().data(), certificates.data(),
             countCertificates(certificates), data.data(), data.size()) == 0;
}

bool Channel::verifyIdentity(
    const std::vector<unsigned char> &certificates) const {
  if (!isEstablished()) {
    throw Error(Error::ChannelUnestablished);
  }
  return autograph_verify_identity(theirPublicKey.value().data(),
                                   certificates.data(),
                                   countCertificates(certificates)) == 0;
}

void Channel::verifyKeyExchange(
    const std::vector<unsigned char> theirHandshake) {
  if (isEstablished()) {
    throw Error(Error::ChannelAlreadyEstablished);
  }
  if (!isInitialized()) {
    throw Error(Error::ChannelUninitialized);
  }
  verified =
      autograph_key_exchange_verify(
          transcript.value().data(), theirPublicKey.value().data(),
          decryptState.value().secretKey.data(), theirHandshake.data()) == 0;
  transcript.reset();
  if (!verified) {
    throw Error(Error::KeyExchangeVerification);
  }
}

}  // namespace Autograph
