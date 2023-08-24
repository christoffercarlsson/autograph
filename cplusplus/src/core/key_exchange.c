#include "key_exchange.h"

#include <string.h>

#include "private.h"
#include "sodium.h"

const unsigned char CONTEXT_INITIATOR = 0;
const unsigned char CONTEXT_RESPONDER = 1;

int autograph_key_exchange_derive_keys(unsigned char *our_secret_key,
                                       unsigned char *their_secret_key,
                                       const unsigned int is_initiator,
                                       unsigned char *our_private_key,
                                       const unsigned char *their_public_key) {
  unsigned char ikm[32];
  int dh_result =
      autograph_crypto_diffie_hellman(ikm, our_private_key, their_public_key);
  int our_key_result = autograph_crypto_kdf(
      our_secret_key, ikm,
      is_initiator == 1 ? &CONTEXT_INITIATOR : &CONTEXT_RESPONDER);
  int their_key_result = autograph_crypto_kdf(
      their_secret_key, ikm,
      is_initiator == 1 ? &CONTEXT_RESPONDER : &CONTEXT_INITIATOR);
  sodium_memzero(our_private_key, 32);
  sodium_memzero(ikm, 32);
  return dh_result == 0 && our_key_result == 0 && their_key_result == 0 ? 0
                                                                        : -1;
}

void autograph_key_exchange_write_transcript(unsigned char *transcript,
                                             const unsigned char *first_key,
                                             const unsigned char *second_key,
                                             const unsigned char *third_key,
                                             const unsigned char *fourth_key) {
  memmove(transcript, first_key, 32);
  memmove(transcript + 32, second_key, 32);
  memmove(transcript + 64, third_key, 32);
  memmove(transcript + 96, fourth_key, 32);
}

int autograph_key_exchange_transcript(
    unsigned char *transcript, const unsigned int is_initiator,
    const unsigned char *our_identity_key,
    const unsigned char *our_ephemeral_key,
    const unsigned char *their_identity_key,
    const unsigned char *their_ephemeral_key) {
  if (is_initiator == 1) {
    autograph_key_exchange_write_transcript(
        transcript, our_identity_key, their_identity_key, our_ephemeral_key,
        their_ephemeral_key);
  } else {
    autograph_key_exchange_write_transcript(
        transcript, their_identity_key, our_identity_key, their_ephemeral_key,
        our_ephemeral_key);
  }
  return 0;
}

int autograph_key_exchange_signature(
    unsigned char *handshake, unsigned char *our_secret_key,
    unsigned char *their_secret_key, const unsigned int is_initiator,
    const unsigned char *our_signature,
    unsigned char *our_private_ephemeral_key,
    const unsigned char *their_public_ephemeral_key) {
  int derive_result = autograph_key_exchange_derive_keys(
      our_secret_key, their_secret_key, is_initiator, our_private_ephemeral_key,
      their_public_ephemeral_key);
  if (derive_result != 0) {
    return -1;
  }
  int ciphertext_result =
      autograph_crypto_encrypt(handshake, our_secret_key, 0, our_signature, 64);
  if (ciphertext_result != 0) {
    return -1;
  }
  return 0;
}

int autograph_key_exchange(unsigned char *transcript, unsigned char *handshake,
                           unsigned char *our_secret_key,
                           unsigned char *their_secret_key,
                           const unsigned int is_initiator,
                           const unsigned char *our_private_identity_key,
                           const unsigned char *our_public_identity_key,
                           unsigned char *our_private_ephemeral_key,
                           const unsigned char *our_public_ephemeral_key,
                           const unsigned char *their_public_identity_key,
                           const unsigned char *their_public_ephemeral_key) {
  int transcript_result = autograph_key_exchange_transcript(
      transcript, is_initiator, our_public_identity_key,
      our_public_ephemeral_key, their_public_identity_key,
      their_public_ephemeral_key);
  if (transcript_result != 0) {
    return -1;
  }
  unsigned char signature[64];
  int sign_result = autograph_crypto_sign(signature, our_private_identity_key,
                                          transcript, 128);
  if (sign_result != 0) {
    return -1;
  }
  return autograph_key_exchange_signature(
      handshake, our_secret_key, their_secret_key, is_initiator, signature,
      our_private_ephemeral_key, their_public_ephemeral_key);
}

int autograph_key_exchange_verify(const unsigned char *transcript,
                                  const unsigned char *their_identity_key,
                                  const unsigned char *their_secret_key,
                                  const unsigned char *ciphertext) {
  unsigned char signature[64];
  int decrypt_result =
      autograph_crypto_decrypt(signature, their_secret_key, 0, ciphertext, 80);
  if (decrypt_result != 0) {
    return -1;
  }
  return autograph_crypto_verify(their_identity_key, transcript, 128,
                                 signature) == 0
             ? 0
             : -1;
}
