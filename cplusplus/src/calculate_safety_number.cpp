#include "autograph/calculate_safety_number.h"

std::string encode_chunk(const Chunk &digest, int i) {
  unsigned int number = ((digest[i] << 24) | (digest[i + 1] << 16) |
                         (digest[i + 2] << 8) | digest[i + 3]) %
                        SAFETY_NUMBER_DIVISOR;
  std::string digits = std::to_string(number);
  digits.resize(5, '0');
  return std::move(digits);
}

Chunk calculate(const Chunk &identity) {
  Chunk digest = hash(identity, SAFETY_NUMBER_ITERATIONS);
  Chunk fingerprint;
  for (int i = 0; i < 30; i += 5) {
    std::string str = encode_chunk(digest, i);
    fingerprint.insert(fingerprint.end(), str.begin(), str.end());
  }
  return std::move(fingerprint);
}

Chunk calculate_safety_number(bool is_initiator, const Chunk &our_identity,
                              const Chunk &their_identity) {
  Chunk our_fingerprint = calculate(our_identity);
  Chunk their_fingerprint = calculate(their_identity);
  if (is_initiator) {
    our_fingerprint.insert(our_fingerprint.end(), their_fingerprint.begin(),
                           their_fingerprint.end());
    return std::move(our_fingerprint);
  }
  their_fingerprint.insert(their_fingerprint.end(), our_fingerprint.begin(),
                           our_fingerprint.end());
  return std::move(their_fingerprint);
}
