#include "autograph/calculate_safety_number.h"

#include <algorithm>
#include <string>

#include "autograph/constants.h"
#include "sodium.h"

constexpr unsigned int FINGERPRINT_CHUNK_SIZE = 5;
constexpr unsigned int FINGERPRINT_SIZE = SAFETY_NUMBER_SIZE / 2;
constexpr unsigned int SAFETY_NUMBER_DIVISOR = 100000;
constexpr unsigned int SAFETY_NUMBER_ITERATIONS = 5200;

bool hash(unsigned char *digest, const unsigned char *identity_key) {
  int initial_result =
      crypto_hash_sha512(digest, identity_key, crypto_sign_PUBLICKEYBYTES);
  if (initial_result != 0) {
    return false;
  }
  for (int i = 1; i < SAFETY_NUMBER_ITERATIONS; i++) {
    int result = crypto_hash_sha512(digest, digest, crypto_hash_sha512_BYTES);
    if (result != 0) {
      return false;
    }
  }
  return true;
}

std::string encode_chunk(const unsigned char *digest, const unsigned int i) {
  int number = ((digest[i] << 24) | (digest[i + 1] << 16) |
                (digest[i + 2] << 8) | digest[i + 3]) %
               SAFETY_NUMBER_DIVISOR;
  std::string digits = std::to_string(number);
  digits.resize(FINGERPRINT_CHUNK_SIZE, '0');
  return std::move(digits);
}

std::string calculate_fingerprint(const unsigned char *identity_key) {
  unsigned char digest[crypto_hash_sha512_BYTES];
  bool hash_result = hash(digest, identity_key);
  std::string fingerprint;
  if (!hash_result) {
    return std::move(fingerprint);
  }
  for (int i = 0; i < FINGERPRINT_SIZE; i += FINGERPRINT_CHUNK_SIZE) {
    std::string chunk = encode_chunk(digest, i);
    fingerprint.insert(fingerprint.end(), chunk.begin(), chunk.end());
  }
  return std::move(fingerprint);
}

std::string calculate(const unsigned char *our_identity_key,
                      const unsigned char *their_identity_key) {
  auto our_fingerprint = calculate_fingerprint(our_identity_key);
  auto their_fingerprint = calculate_fingerprint(their_identity_key);
  std::string safety_number;
  if (std::lexicographical_compare(
          our_fingerprint.begin(), our_fingerprint.end(),
          their_fingerprint.begin(), their_fingerprint.end())) {
    safety_number.insert(safety_number.end(), our_fingerprint.begin(),
                         our_fingerprint.end());
    safety_number.insert(safety_number.end(), their_fingerprint.begin(),
                         their_fingerprint.end());
  } else {
    safety_number.insert(safety_number.end(), their_fingerprint.begin(),
                         their_fingerprint.end());
    safety_number.insert(safety_number.end(), our_fingerprint.begin(),
                         our_fingerprint.end());
  }
  return std::move(safety_number);
}

bool calculate_safety_number(unsigned char *safety_number,
                             const unsigned char *our_identity_key,
                             const unsigned char *their_identity_key) {
  auto result = calculate(our_identity_key, their_identity_key);
  if (result.size() != SAFETY_NUMBER_SIZE) {
    return false;
  }
  std::move(result.begin(), result.end(), safety_number);
  return true;
}
