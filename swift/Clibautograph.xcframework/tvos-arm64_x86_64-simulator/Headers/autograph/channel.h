#ifndef AUTOGRAPH_CHANNEL_H
#define AUTOGRAPH_CHANNEL_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_key_exchange(unsigned char *transcript, unsigned char *handshake,
                           unsigned char *our_secret_key,
                           unsigned char *their_secret_key,
                           const unsigned int is_initiator,
                           const unsigned char *our_private_identity_key,
                           const unsigned char *our_public_identity_key,
                           unsigned char *our_private_ephemeral_key,
                           const unsigned char *our_public_ephemeral_key,
                           const unsigned char *their_public_identity_key,
                           const unsigned char *their_public_ephemeral_key);

int autograph_key_exchange_signature(
    unsigned char *handshake, unsigned char *our_secret_key,
    unsigned char *their_secret_key, const unsigned int is_initiator,
    const unsigned char *our_signature,
    unsigned char *our_private_ephemeral_key,
    const unsigned char *their_public_ephemeral_key);

int autograph_key_exchange_transcript(unsigned char *transcript,
                                      const unsigned int is_initiator,
                                      const unsigned char *our_identity_key,
                                      const unsigned char *our_ephemeral_key,
                                      const unsigned char *their_identity_key,
                                      const unsigned char *their_ephemeral_key);

int autograph_key_exchange_verify(const unsigned char *transcript,
                                  const unsigned char *their_identity_key,
                                  const unsigned char *their_secret_key,
                                  const unsigned char *ciphertext);

int autograph_decrypt(unsigned char *plaintext, unsigned char *plaintext_size,
                      unsigned char *message_index,
                      unsigned char *decrypt_index, unsigned char *skipped_keys,
                      unsigned char *key, const unsigned char *message,
                      const unsigned int message_size);

int autograph_encrypt(unsigned char *message, unsigned char *index,
                      unsigned char *key, const unsigned char *plaintext,
                      const unsigned int plaintext_size);

unsigned int autograph_read_uint32(const unsigned char *bytes);

unsigned long long autograph_read_uint64(const unsigned char *bytes);

int autograph_safety_number(unsigned char *safety_number,
                            const unsigned char *our_identity_key,
                            const unsigned char *their_identity_key);

int autograph_sign_data(unsigned char *signature,
                        const unsigned char *our_private_key,
                        const unsigned char *their_public_key,
                        const unsigned char *data,
                        const unsigned int data_size);

int autograph_sign_identity(unsigned char *signature,
                            const unsigned char *our_private_key,
                            const unsigned char *their_public_key);

int autograph_subject(unsigned char *subject,
                      const unsigned char *their_public_key,
                      const unsigned char *data, const unsigned int data_size);

int autograph_verify_data(const unsigned char *their_public_key,
                          const unsigned char *certificates,
                          const unsigned int certificate_count,
                          const unsigned char *data,
                          const unsigned int data_size);

int autograph_verify_identity(const unsigned char *their_public_key,
                              const unsigned char *certificates,
                              const unsigned int certificate_count);

#ifdef __cplusplus
}  // extern "C"

#include <optional>
#include <tuple>

#include "key_pair.h"
#include "sign.h"

namespace Autograph {

class DecryptionState {
 public:
  std::vector<unsigned char> decryptIndex;
  std::vector<unsigned char> messageIndex;
  std::vector<unsigned char> plaintextSize;
  std::vector<unsigned char> secretKey;
  std::vector<unsigned char> skippedKeys;

  DecryptionState(std::vector<unsigned char> secretKey);

  unsigned long long readMessageIndex() const;

  void resizeData(std::vector<unsigned char> &plaintext) const;

 private:
  unsigned int readPlaintextSize() const;
};

class EncryptionState {
 public:
  std::vector<unsigned char> messageIndex;
  std::vector<unsigned char> secretKey;

  EncryptionState(std::vector<unsigned char> secretKey);

  unsigned long long readMessageIndex() const;
};

class Channel {
 public:
  Channel(const SignFunction sign,
          const std::vector<unsigned char> ourIdentityKey);

  std::vector<unsigned char> calculateSafetyNumber() const;

  void close();

  std::tuple<unsigned long long, std::vector<unsigned char>> decrypt(
      const std::vector<unsigned char> message);

  std::tuple<unsigned long long, std::vector<unsigned char>> encrypt(
      const std::vector<unsigned char> &plaintext);

  bool isClosed() const;

  bool isEstablished() const;

  bool isInitialized() const;

  std::vector<unsigned char> performKeyExchange(
      const bool isInitiator, KeyPair &ourEphemeralKeyPair,
      const std::vector<unsigned char> theirIdentityKey,
      const std::vector<unsigned char> theirEphemeralKey);

  std::vector<unsigned char> signData(
      const std::vector<unsigned char> &data) const;

  std::vector<unsigned char> signIdentity() const;

  bool verifyData(const std::vector<unsigned char> &certificates,
                  const std::vector<unsigned char> &data) const;

  bool verifyIdentity(const std::vector<unsigned char> &certificates) const;

  void verifyKeyExchange(const std::vector<unsigned char> theirHandshake);

 private:
  std::optional<DecryptionState> decryptState;
  std::optional<EncryptionState> encryptState;
  const std::vector<unsigned char> ourIdentityKey;
  const SignFunction sign;
  std::optional<std::vector<unsigned char>> theirPublicKey;
  std::optional<std::vector<unsigned char>> transcript;
  bool verified;
};

}  // namespace Autograph

#endif

#endif
