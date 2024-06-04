#ifndef AUTOGRAPH_H
#define AUTOGRAPH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "autograph.h"

#ifdef __cplusplus
extern "C" {
#endif

bool autograph_ready();

bool autograph_identity_key_pair(uint8_t *key_pair);

bool autograph_session_key_pair(uint8_t *key_pair);

void autograph_get_public_key(uint8_t *public_key, const uint8_t *key_pair);

bool autograph_authenticate(uint8_t *safety_number,
                            const uint8_t *our_identity_key_pair,
                            const uint8_t *their_identity_key);

bool autograph_certify(uint8_t *signature, const uint8_t *our_identity_key_pair,
                       const uint8_t *their_identity_key, const uint8_t *data,
                       const size_t data_size);

bool autograph_verify(const uint8_t *owner_identity_key,
                      const uint8_t *certifier_identity_key,
                      const uint8_t *signature, const uint8_t *data,
                      const size_t data_size);

bool autograph_key_exchange(uint8_t *transcript, uint8_t *our_signature,
                            uint8_t *sending_key, uint8_t *receiving_key,
                            const bool is_initiator,
                            const uint8_t *our_identity_key_pair,
                            const uint8_t *our_session_key_pair,
                            const uint8_t *their_identity_key,
                            const uint8_t *their_session_key);

bool autograph_verify_key_exchange(const uint8_t *transcript,
                                   const uint8_t *our_identity_key_pair,
                                   const uint8_t *their_identity_key,
                                   const uint8_t *their_signature);

bool autograph_encrypt(uint32_t *index, uint8_t *ciphertext, const uint8_t *key,
                       uint8_t *nonce, const uint8_t *plaintext,
                       const size_t plaintext_size);

bool autograph_decrypt(uint32_t *index, uint8_t *plaintext,
                       size_t *plaintext_size, const uint8_t *key,
                       uint8_t *nonce, uint32_t *skipped_indexes,
                       const size_t skipped_indexes_size,
                       const uint8_t *ciphertext, const size_t ciphertext_size);

size_t autograph_key_pair_size();

size_t autograph_nonce_size();

size_t autograph_public_key_size();

size_t autograph_safety_number_size();

size_t autograph_secret_key_size();

size_t autograph_signature_size();

size_t autograph_transcript_size();

size_t autograph_ciphertext_size(const size_t plaintext_size);

size_t autograph_plaintext_size(const size_t ciphertext_size);

void autograph_use_key_pairs(uint8_t *identity_key_pair,
                             uint8_t *session_key_pair,
                             const uint8_t *our_identity_key_pair,
                             const uint8_t *our_session_key_pair);

void autograph_use_public_keys(uint8_t *identity_key, uint8_t *session_key,
                               const uint8_t *their_identity_key,
                               const uint8_t *their_session_key);

#ifdef __cplusplus
}  // extern "C"

#include <array>
#include <optional>
#include <tuple>
#include <vector>

namespace Autograph {

constexpr size_t KEY_PAIR_SIZE = 64;
constexpr size_t NONCE_SIZE = 12;
constexpr size_t PUBLIC_KEY_SIZE = 32;
constexpr size_t SAFETY_NUMBER_SIZE = 64;
constexpr size_t SECRET_KEY_SIZE = 32;
constexpr size_t SIGNATURE_SIZE = 64;
constexpr size_t TRANSCRIPT_SIZE = 64;
constexpr size_t SKIPPED_INDEXES_COUNT = 128;

using Bytes = std::vector<uint8_t>;
using KeyPair = std::array<uint8_t, KEY_PAIR_SIZE>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;
using PublicKey = std::array<uint8_t, PUBLIC_KEY_SIZE>;
using SafetyNumber = std::array<uint8_t, SAFETY_NUMBER_SIZE>;
using SecretKey = std::array<uint8_t, SECRET_KEY_SIZE>;
using Signature = std::array<uint8_t, SIGNATURE_SIZE>;
using SkippedIndexes = std::array<uint32_t, SKIPPED_INDEXES_COUNT>;
using Transcript = std::array<uint8_t, TRANSCRIPT_SIZE>;

bool ready();

std::tuple<bool, KeyPair> generateIdentityKeyPair();

std::tuple<bool, KeyPair> generateSessionKeyPair();

PublicKey getPublicKey(const KeyPair &keyPair);

std::tuple<PublicKey, PublicKey> getPublicKeys(const KeyPair &identityKeyPair,
                                               const KeyPair &sessionKeyPair);

std::tuple<bool, SafetyNumber> authenticate(const KeyPair &ourIdentityKeyPair,
                                            const PublicKey &theirIdentityKey);

std::tuple<bool, Signature> certify(const KeyPair &ourIdentityKeyPair,
                                    const PublicKey &theirIdentityKey,
                                    const std::optional<Bytes> &data);

bool verify(const PublicKey &ownerIdentityKey,
            const PublicKey &certifierIdentityKey, const Signature &signature,
            const std::optional<Bytes> &data);

std::tuple<bool, Transcript, Signature, SecretKey, SecretKey> keyExchange(
    const bool isInitiator, const KeyPair &ourIdentityKeyPair,
    const KeyPair &ourSessionKeyPair, const PublicKey &theirIdentityKey,
    const PublicKey &theirSessionKey);

bool verifyKeyExchange(const Transcript &transcript,
                       const KeyPair &ourIdentityKeyPair,
                       const PublicKey &theirIdentityKey,
                       const Signature &theirSignature);

std::tuple<bool, uint32_t, Bytes> encrypt(const SecretKey &key, Nonce &nonce,
                                          const Bytes &plaintext);

std::tuple<bool, uint32_t, Bytes> decrypt(const SecretKey &key, Nonce &nonce,
                                          SkippedIndexes &skippedIndexes,
                                          const Bytes &ciphertext);

class Channel {
 public:
  Channel(const KeyPair &ourIdentityKeyPair, const KeyPair &ourSessionKeyPair,
          const PublicKey &theirIdentityKey, const PublicKey &theirSessionKey);

  std::tuple<bool, SafetyNumber> authenticate() const;

  std::tuple<bool, Signature> certify(const std::optional<Bytes> &data) const;

  bool verify(const PublicKey &certifierIdentityKey, const Signature &signature,
              const std::optional<Bytes> &data) const;

  std::tuple<bool, Signature> keyExchange(const bool isInitiator);

  bool verifyKeyExchange(const Signature &signature);

  std::tuple<bool, uint32_t, Bytes> encrypt(const Bytes &plaintext);

  std::tuple<bool, uint32_t, Bytes> decrypt(const Bytes &ciphertext);

 private:
  KeyPair ourIdentityKeyPair;
  KeyPair ourSessionKeyPair;
  PublicKey theirIdentityKey;
  PublicKey theirSessionKey;
  Transcript transcript;
  SecretKey sendingKey;
  SecretKey receivingKey;
  Nonce sendingNonce;
  Nonce receivingNonce;
  SkippedIndexes skippedIndexes;
};

}  // namespace Autograph
#endif

#endif
