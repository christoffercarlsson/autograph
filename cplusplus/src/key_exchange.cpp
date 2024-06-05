#include <string.h>

#include "autograph.h"
#include "constants.h"
#include "external.h"
#include "support.h"

extern "C" {

void calculate_secret_keys(uint8_t *sending_key, uint8_t *receiving_key,
                           const bool is_initiator, const uint8_t *okm) {
  if (is_initiator) {
    memmove(sending_key, okm, SECRET_KEY_SIZE);
    memmove(receiving_key, okm + SECRET_KEY_SIZE, SECRET_KEY_SIZE);
  } else {
    memmove(receiving_key, okm, SECRET_KEY_SIZE);
    memmove(sending_key, okm + SECRET_KEY_SIZE, SECRET_KEY_SIZE);
  }
}

bool derive_secret_keys(uint8_t *sending_key, uint8_t *receiving_key,
                        const bool is_initiator,
                        const uint8_t *our_session_key_pair,
                        const uint8_t *their_session_key) {
  uint8_t shared_secret[SHARED_SECRET_SIZE];
  uint8_t okm[OKM_SIZE];
  uint8_t salt[SALT_SIZE];
  zeroize(salt, SALT_SIZE);
  uint8_t info[INFO_SIZE] = INFO;
  bool dh_success =
      diffie_hellman(shared_secret, our_session_key_pair, their_session_key);
  bool kdf_success = hkdf(okm, OKM_SIZE, shared_secret, SHARED_SECRET_SIZE,
                          salt, SALT_SIZE, info, INFO_SIZE);
  calculate_secret_keys(sending_key, receiving_key, is_initiator, okm);
  return dh_success && kdf_success;
}

void calculate_transcript(uint8_t *transcript, const bool is_initiator,
                          const uint8_t *our_session_key_pair,
                          const uint8_t *their_session_key) {
  uint8_t our_session_key[PUBLIC_KEY_SIZE];
  autograph_get_public_key(our_session_key, our_session_key_pair);
  if (is_initiator) {
    memmove(transcript, our_session_key, PUBLIC_KEY_SIZE);
    memmove(transcript + PUBLIC_KEY_SIZE, their_session_key, PUBLIC_KEY_SIZE);
  } else {
    memmove(transcript, their_session_key, PUBLIC_KEY_SIZE);
    memmove(transcript + PUBLIC_KEY_SIZE, our_session_key, PUBLIC_KEY_SIZE);
  }
}

bool autograph_key_exchange(uint8_t *transcript, uint8_t *our_signature,
                            uint8_t *sending_key, uint8_t *receiving_key,
                            const bool is_initiator,
                            const uint8_t *our_identity_key_pair,
                            const uint8_t *our_session_key_pair,
                            const uint8_t *their_identity_key,
                            const uint8_t *their_session_key) {
  calculate_transcript(transcript, is_initiator, our_session_key_pair,
                       their_session_key);
  bool key_success =
      derive_secret_keys(sending_key, receiving_key, is_initiator,
                         our_session_key_pair, their_session_key);
  bool certify_success =
      autograph_certify(our_signature, our_identity_key_pair,
                        their_identity_key, transcript, TRANSCRIPT_SIZE);
  return key_success && certify_success;
}

bool autograph_verify_key_exchange(const uint8_t *transcript,
                                   const uint8_t *our_identity_key_pair,
                                   const uint8_t *their_identity_key,
                                   const uint8_t *their_signature) {
  uint8_t our_identity_key[PUBLIC_KEY_SIZE];
  autograph_get_public_key(our_identity_key, our_identity_key_pair);
  return autograph_verify(our_identity_key, their_identity_key, their_signature,
                          transcript, TRANSCRIPT_SIZE);
}

}  // extern "C"

namespace Autograph {

std::tuple<bool, Transcript, Signature, SecretKey, SecretKey> keyExchange(
    const bool isInitiator, const KeyPair &ourIdentityKeyPair,
    const KeyPair &ourSessionKeyPair, const PublicKey &theirIdentityKey,
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
