#include <algorithm>
#include <vector>

#include "autograph.h"
#include "constants.hpp"
#include "crypto.hpp"
#include "sodium.h"
#include "types.hpp"

namespace autograph {

void write_transcript(unsigned char *transcript, const unsigned char *first_key,
                      const unsigned char *second_key,
                      const unsigned char *third_key,
                      const unsigned char *fourth_key) {
  std::copy(first_key, first_key + PUBLIC_KEY_SIZE, transcript);
  std::copy(second_key, second_key + PUBLIC_KEY_SIZE,
            transcript + PUBLIC_KEY_SIZE);
  std::copy(third_key, third_key + PUBLIC_KEY_SIZE,
            transcript + 2 * PUBLIC_KEY_SIZE);
  std::copy(fourth_key, fourth_key + PUBLIC_KEY_SIZE,
            transcript + 3 * PUBLIC_KEY_SIZE);
}

void calculate_transcript(unsigned char *transcript, const bool is_initiator,
                          const unsigned char *our_identity_key,
                          const unsigned char *our_ephemeral_key,
                          const unsigned char *their_identity_key,
                          const unsigned char *their_ephemeral_key) {
  if (is_initiator) {
    write_transcript(transcript, our_identity_key, their_identity_key,
                     our_ephemeral_key, their_ephemeral_key);
  } else {
    write_transcript(transcript, their_identity_key, our_identity_key,
                     their_ephemeral_key, our_ephemeral_key);
  }
}

bool calculate_ciphertext(unsigned char *message,
                          const unsigned char *transcript,
                          const unsigned char *our_private_key,
                          const unsigned char *our_secret_key) {
  Bytes signature(SIGNATURE_SIZE);
  bool signature_result =
      sign(signature.data(), our_private_key, transcript, TRANSCRIPT_SIZE);
  if (!signature_result) {
    return false;
  }
  return encrypt(message, our_secret_key, 0, signature.data(),
                 signature.size());
}

bool derive_keys(unsigned char *our_secret_key, unsigned char *their_secret_key,
                 const bool is_initiator, unsigned char *our_private_key,
                 const unsigned char *their_public_key) {
  Bytes ikm(DH_OUTPUT_SIZE);
  bool dh_result =
      diffie_hellman(ikm.data(), our_private_key, their_public_key);
  bool our_key_result =
      kdf(our_secret_key, ikm.data(),
          is_initiator ? CONTEXT_INITIATOR : CONTEXT_RESPONDER);
  bool their_key_result =
      kdf(their_secret_key, ikm.data(),
          is_initiator ? CONTEXT_RESPONDER : CONTEXT_INITIATOR);
  sodium_memzero(our_private_key, PRIVATE_KEY_SIZE);
  sodium_memzero(ikm.data(), DH_OUTPUT_SIZE);
  return dh_result && our_key_result && their_key_result;
}

}  // namespace autograph

int autograph_handshake(unsigned char *transcript, unsigned char *message,
                        unsigned char *our_secret_key,
                        unsigned char *their_secret_key,
                        const unsigned int is_initiator,
                        const unsigned char *our_private_identity_key,
                        const unsigned char *our_public_identity_key,
                        unsigned char *our_private_ephemeral_key,
                        const unsigned char *our_public_ephemeral_key,
                        const unsigned char *their_public_identity_key,
                        const unsigned char *their_public_ephemeral_key) {
  autograph::calculate_transcript(
      transcript, is_initiator == 1, our_public_identity_key,
      our_public_ephemeral_key, their_public_identity_key,
      their_public_ephemeral_key);
  bool derive_result = autograph::derive_keys(
      our_secret_key, their_secret_key, is_initiator == 1,
      our_private_ephemeral_key, their_public_ephemeral_key);
  if (!derive_result) {
    return -1;
  }
  bool ciphertext_result = autograph::calculate_ciphertext(
      message, transcript, our_private_identity_key, our_private_ephemeral_key);
  if (!ciphertext_result) {
    return -1;
  }
  return 0;
}
