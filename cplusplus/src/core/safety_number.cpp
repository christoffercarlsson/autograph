#include "autograph/core/safety_number.h"

#include <algorithm>
#include <string>

#include "autograph/core/key_pair.h"
#include "autograph/crypto/hash.h"

std::string autograph_core_safety_number_chunk(const unsigned char *digest,
                                               const unsigned int i) {
  int number = ((digest[i] << 24) | (digest[i + 1] << 16) |
                (digest[i + 2] << 8) | digest[i + 3]) %
               autograph_core_safety_number_DIVISOR;
  std::string digits = std::to_string(number);
  digits.resize(autograph_core_safety_number_CHUNK_SIZE, '0');
  return std::move(digits);
}

std::string autograph_core_safety_number_fingerprint(
    const unsigned char *identity_key) {
  unsigned char digest[autograph_crypto_hash_DIGEST_SIZE];
  bool hash_result = autograph_crypto_hash(
      digest, identity_key, autograph_core_key_pair_PUBLIC_KEY_SIZE,
      autograph_core_safety_number_ITERATIONS);
  std::string fingerprint;
  if (!hash_result) {
    return std::move(fingerprint);
  }
  for (int i = 0; i < autograph_core_safety_number_FINGERPRINT_SIZE;
       i += autograph_core_safety_number_CHUNK_SIZE) {
    std::string chunk = autograph_core_safety_number_chunk(digest, i);
    fingerprint.insert(fingerprint.end(), chunk.begin(), chunk.end());
  }
  return std::move(fingerprint);
}

int autograph_core_safety_number(unsigned char *safety_number,
                                 const unsigned char *our_identity_key,
                                 const unsigned char *their_identity_key) {
  auto our_fingerprint =
      autograph_core_safety_number_fingerprint(our_identity_key);
  auto their_fingerprint =
      autograph_core_safety_number_fingerprint(their_identity_key);
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
  if (result.size() != autograph_core_safety_number_SIZE) {
    return -1;
  }
  std::move(result.begin(), result.end(), safety_number);
  return 0;
}
