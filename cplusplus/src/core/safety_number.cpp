#include <algorithm>
#include <string>
#include <vector>

#include "autograph.h"
#include "constants.hpp"
#include "crypto.hpp"

namespace autograph {

std::string encode_chunk(const unsigned char *digest, const unsigned int i) {
  const unsigned long long a = digest[i];
  const unsigned long long b = digest[i + 1];
  const unsigned long long c = digest[i + 2];
  const unsigned long long d = digest[i + 3];
  const unsigned long long e = digest[i + 4];
  const unsigned int number =
      (a << 32 | b << 24 | c << 16 | d << 8 | e) % SAFETY_NUMBER_DIVISOR;
  std::string digits = std::to_string(number);
  digits.resize(SAFETY_NUMBER_CHUNK_SIZE, 0);
  return std::move(digits);
}

std::string calculate_fingerprint(const unsigned char *identity_key) {
  std::vector<unsigned char> digest(DIGEST_SIZE);
  bool hash_result = hash(digest.data(), identity_key, PUBLIC_KEY_SIZE,
                          SAFETY_NUMBER_ITERATIONS);
  std::string fingerprint;
  if (!hash_result) {
    return std::move(fingerprint);
  }
  for (int i = 0; i < SAFETY_NUMBER_FINGERPRINT_SIZE;
       i += SAFETY_NUMBER_CHUNK_SIZE) {
    std::string chunk = encode_chunk(digest.data(), i);
    fingerprint.insert(fingerprint.end(), chunk.begin(), chunk.end());
  }
  return std::move(fingerprint);
}

}  // namespace autograph

int autograph_safety_number(unsigned char *safety_number,
                            const unsigned char *our_identity_key,
                            const unsigned char *their_identity_key) {
  auto our_fingerprint = autograph::calculate_fingerprint(our_identity_key);
  auto their_fingerprint = autograph::calculate_fingerprint(their_identity_key);
  std::string result;
  if (std::lexicographical_compare(
          our_fingerprint.begin(), our_fingerprint.end(),
          their_fingerprint.begin(), their_fingerprint.end())) {
    result.insert(result.end(), our_fingerprint.begin(), our_fingerprint.end());
    result.insert(result.end(), their_fingerprint.begin(),
                  their_fingerprint.end());
  } else {
    result.insert(result.end(), their_fingerprint.begin(),
                  their_fingerprint.end());
    result.insert(result.end(), our_fingerprint.begin(), our_fingerprint.end());
  }
  if (result.size() != autograph::SAFETY_NUMBER_SIZE) {
    return -1;
  }
  std::move(result.begin(), result.end(), safety_number);
  return 0;
}
