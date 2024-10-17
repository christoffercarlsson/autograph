#ifndef AUTOGRAPH_H
#define AUTOGRAPH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool autograph_ready();

bool autograph_identity_key_pair(uint8_t *key_pair);

bool autograph_session_key_pair(uint8_t *key_pair);

void autograph_get_identity_public_key(uint8_t *public_key,
                                       const uint8_t *key_pair);

void autograph_get_session_public_key(uint8_t *public_key,
                                      const uint8_t *key_pair);

bool autograph_authenticate(uint8_t *safety_number,
                            const uint8_t *our_identity_key_pair,
                            const uint8_t *our_id, const size_t our_id_size,
                            const uint8_t *their_identity_key,
                            const uint8_t *their_id,
                            const size_t their_id_size);

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

bool autograph_generate_secret_key(uint8_t *key);

bool autograph_encrypt(uint32_t *index, uint8_t *ciphertext, const uint8_t *key,
                       uint8_t *nonce, const uint8_t *plaintext,
                       const size_t plaintext_size);

bool autograph_decrypt(uint32_t *index, uint8_t *plaintext,
                       size_t *plaintext_size, const uint8_t *key,
                       uint8_t *nonce, uint8_t *skipped_indexes,
                       const size_t skipped_indexes_size,
                       const uint8_t *ciphertext, const size_t ciphertext_size);

size_t autograph_identity_key_pair_size();

size_t autograph_session_key_pair_size();

size_t autograph_identity_public_key_size();

size_t autograph_session_public_key_size();

size_t autograph_nonce_size();

size_t autograph_safety_number_size();

size_t autograph_secret_key_size();

size_t autograph_signature_size();

size_t autograph_skipped_indexes_size(const uint16_t count);

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

#include <optional>
#include <tuple>
#include <vector>

namespace Autograph {

using Bytes = std::vector<uint8_t>;

bool ready();

std::tuple<bool, Bytes> generateIdentityKeyPair();

std::tuple<bool, Bytes> generateSessionKeyPair();

Bytes getIdentityPublicKey(const Bytes &keyPair);

Bytes getSessionPublicKey(const Bytes &keyPair);

std::tuple<Bytes, Bytes> getPublicKeys(const Bytes &identityKeyPair,
                                       const Bytes &sessionKeyPair);

std::tuple<bool, Bytes> authenticate(const Bytes &ourIdentityKeyPair,
                                     const Bytes &ourId,
                                     const Bytes &theirIdentityKey,
                                     const Bytes &theirId);

std::tuple<bool, Bytes> certify(const Bytes &ourIdentityKeyPair,
                                const Bytes &theirIdentityKey,
                                const std::optional<Bytes> &data);

bool verify(const Bytes &ownerIdentityKey, const Bytes &certifierIdentityKey,
            const Bytes &signature, const std::optional<Bytes> &data);

std::tuple<bool, Bytes, Bytes, Bytes, Bytes> keyExchange(
    const bool isInitiator, const Bytes &ourIdentityKeyPair,
    const Bytes &ourSessionKeyPair, const Bytes &theirIdentityKey,
    const Bytes &theirSessionKey);

bool verifyKeyExchange(const Bytes &transcript, const Bytes &ourIdentityKeyPair,
                       const Bytes &theirIdentityKey,
                       const Bytes &theirSignature);

std::tuple<bool, Bytes> generateSecretKey();

Bytes createNonce();

Bytes createSkippedIndexes(const std::optional<uint16_t> count);

std::tuple<bool, uint32_t, Bytes> encrypt(const Bytes &key, Bytes &nonce,
                                          const Bytes &plaintext);

std::tuple<bool, uint32_t, Bytes> decrypt(const Bytes &key, Bytes &nonce,
                                          Bytes &skippedIndexes,
                                          const Bytes &ciphertext);

class Channel {
 public:
  Channel();

  std::tuple<Bytes, Bytes> useKeyPairs(const Bytes &ourIdentityKeyPair,
                                       const Bytes &ourSessionKeyPair);

  void usePublicKeys(const Bytes &theirIdentityKey,
                     const Bytes &theirSessionKey);

  std::tuple<bool, Bytes> authenticate(const Bytes &ourId,
                                       const Bytes &theirId) const;

  std::tuple<bool, Bytes> certify(const std::optional<Bytes> &data) const;

  bool verify(const Bytes &certifierIdentityKey, const Bytes &signature,
              const std::optional<Bytes> &data) const;

  std::tuple<bool, Bytes> keyExchange(const bool isInitiator);

  bool verifyKeyExchange(const Bytes &signature);

  std::tuple<bool, uint32_t, Bytes> encrypt(const Bytes &plaintext);

  std::tuple<bool, uint32_t, Bytes> decrypt(const Bytes &ciphertext);

 private:
  Bytes ourIdentityKeyPair;
  Bytes ourSessionKeyPair;
  Bytes theirIdentityKey;
  Bytes theirSessionKey;
  Bytes transcript;
  Bytes sendingKey;
  Bytes receivingKey;
  Bytes sendingNonce;
  Bytes receivingNonce;
  Bytes skippedIndexes;
};

}  // namespace Autograph
#endif

#endif
