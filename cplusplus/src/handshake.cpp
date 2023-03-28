#include "autograph/handshake.h"

#include <vector>

#include "autograph/aes.h"
#include "autograph/constants.h"
#include "autograph/derive_secret_keys.h"
#include "autograph/sign_message.h"
#include "sodium.h"

void calculate_transcript(unsigned char *transcript, bool is_initiator,
                          const unsigned char *our_identity_key,
                          const unsigned char *our_ephemeral_key,
                          const unsigned char *their_identity_key,
                          const unsigned char *their_ephemeral_key) {
  auto result = std::vector<unsigned char>(TRANSCRIPT_SIZE);
  result.insert(result.end(), our_identity_key,
                our_identity_key + PUBLIC_KEY_SIZE);
  result.insert(result.end(), our_ephemeral_key,
                our_ephemeral_key + PUBLIC_KEY_SIZE);
  result.insert(result.end(), their_identity_key,
                their_identity_key + PUBLIC_KEY_SIZE);
  result.insert(result.end(), their_ephemeral_key,
                their_ephemeral_key + PUBLIC_KEY_SIZE);
  std::move(result.begin(), result.end(), transcript);
}

bool calculate_ciphertext(unsigned char *ciphertext,
                          const unsigned char *transcript,
                          const unsigned char *our_private_key,
                          const unsigned char *our_secret_key) {
  unsigned char signature[SIGNATURE_SIZE];
  bool signature_result =
      sign_message(signature, our_private_key, transcript, TRANSCRIPT_SIZE);
  if (!signature_result) {
    return false;
  }
  return aes_encrypt(ciphertext, our_secret_key, 0, signature, SIGNATURE_SIZE);
}

bool handshake(unsigned char *transcript, unsigned char *ciphertext,
               unsigned char *our_secret_key, unsigned char *their_secret_key,
               bool is_initiator, const unsigned char *our_private_identity_key,
               const unsigned char *our_public_identity_key,
               unsigned char *our_private_ephemeral_key,
               const unsigned char *our_public_ephemeral_key,
               const unsigned char *their_public_identity_key,
               const unsigned char *their_public_ephemeral_key) {
  calculate_transcript(transcript, is_initiator, our_public_identity_key,
                       our_public_ephemeral_key, their_public_identity_key,
                       their_public_ephemeral_key);
  bool derive_result =
      derive_secret_keys(our_secret_key, their_secret_key, is_initiator,
                         our_private_ephemeral_key, their_public_ephemeral_key);
  if (!derive_result) {
    return false;
  }
  return calculate_ciphertext(ciphertext, transcript, our_private_identity_key,
                              our_private_ephemeral_key);
}
