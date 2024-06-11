#include <string.h>

#include "autograph.h"
#include "primitives.h"

extern "C" {

void calculate_secret_keys(uint8_t *sending_key, uint8_t *receiving_key,
                           const bool is_initiator, const uint8_t *okm) {
  size_t secret_key_size = autograph_secret_key_size();
  if (is_initiator) {
    memmove(sending_key, okm, secret_key_size);
    memmove(receiving_key, okm + secret_key_size, secret_key_size);
  } else {
    memmove(receiving_key, okm, secret_key_size);
    memmove(sending_key, okm + secret_key_size, secret_key_size);
  }
}

bool derive_secret_keys(uint8_t *sending_key, uint8_t *receiving_key,
                        const bool is_initiator,
                        const uint8_t *our_session_key_pair,
                        const uint8_t *their_session_key) {
  uint8_t shared_secret[autograph_primitive_shared_secret_size()];
  uint8_t okm[autograph_secret_key_size() * 2];
  bool dh_success = autograph_primitive_diffie_hellman(
      shared_secret, our_session_key_pair, their_session_key);
  bool kdf_success = autograph_primitive_kdf(okm, shared_secret);
  calculate_secret_keys(sending_key, receiving_key, is_initiator, okm);
  return dh_success && kdf_success;
}

void calculate_transcript(uint8_t *transcript, const bool is_initiator,
                          const uint8_t *our_session_key_pair,
                          const uint8_t *their_session_key) {
  size_t public_key_size = autograph_session_public_key_size();
  uint8_t our_session_key[public_key_size];
  autograph_get_session_public_key(our_session_key, our_session_key_pair);
  if (is_initiator) {
    memmove(transcript, our_session_key, public_key_size);
    memmove(transcript + public_key_size, their_session_key, public_key_size);
  } else {
    memmove(transcript, their_session_key, public_key_size);
    memmove(transcript + public_key_size, our_session_key, public_key_size);
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
  bool certify_success = autograph_certify(our_signature, our_identity_key_pair,
                                           their_identity_key, transcript,
                                           autograph_transcript_size());
  return key_success && certify_success;
}

bool autograph_verify_key_exchange(const uint8_t *transcript,
                                   const uint8_t *our_identity_key_pair,
                                   const uint8_t *their_identity_key,
                                   const uint8_t *their_signature) {
  uint8_t our_identity_key[autograph_identity_public_key_size()];
  autograph_get_identity_public_key(our_identity_key, our_identity_key_pair);
  return autograph_verify(our_identity_key, their_identity_key, their_signature,
                          transcript, autograph_transcript_size());
}

size_t autograph_transcript_size() {
  return autograph_session_public_key_size() * 2;
}

}  // extern "C"

namespace Autograph {

std::tuple<bool, Bytes, Bytes, Bytes, Bytes> keyExchange(
    const bool isInitiator, const Bytes &ourIdentityKeyPair,
    const Bytes &ourSessionKeyPair, const Bytes &theirIdentityKey,
    const Bytes &theirSessionKey) {
  Bytes transcript(autograph_transcript_size());
  Bytes ourSignature(autograph_signature_size());
  Bytes sendingKey(autograph_secret_key_size());
  Bytes receivingKey(autograph_secret_key_size());
  bool success = autograph_key_exchange(
      transcript.data(), ourSignature.data(), sendingKey.data(),
      receivingKey.data(), isInitiator, ourIdentityKeyPair.data(),
      ourSessionKeyPair.data(), theirIdentityKey.data(),
      theirSessionKey.data());
  return {success, transcript, ourSignature, sendingKey, receivingKey};
}

bool verifyKeyExchange(const Bytes &transcript, const Bytes &ourIdentityKeyPair,
                       const Bytes &theirIdentityKey,
                       const Bytes &theirSignature) {
  return autograph_verify_key_exchange(
      transcript.data(), ourIdentityKeyPair.data(), theirIdentityKey.data(),
      theirSignature.data());
}

}  // namespace Autograph
