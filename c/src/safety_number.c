#include <stdio.h>
#include <string.h>

#include "autograph.h"
#include "crypto.h"

int encode_chunk(unsigned char *fingerprint, const unsigned char *digest,
                 const unsigned int i) {
  const unsigned long long a = digest[i];
  const unsigned long long b = digest[i + 1];
  const unsigned long long c = digest[i + 2];
  const unsigned long long d = digest[i + 3];
  const unsigned long long e = digest[i + 4];
  const unsigned int number =
      (a << 32 | b << 24 | c << 16 | d << 8 | e) % 100000;
  char digits[6];
  int result = snprintf(digits, 6, "%05u", number);
  if (result >= 0 && result < 6) {
    return -1;
  }
  fingerprint[i] = digits[0];
  fingerprint[i + 1] = digits[1];
  fingerprint[i + 2] = digits[2];
  fingerprint[i + 3] = digits[3];
  fingerprint[i + 4] = digits[4];
  return 0;
}

int calculate_fingerprint(unsigned char *fingerprint,
                          const unsigned char *identity_key) {
  unsigned char digest[64];
  int hash_result = hash(digest, identity_key, 32, 5200);
  if (hash_result != 0) {
    return -1;
  }
  for (int i = 0; i < 30; i += 5) {
    int encode_result = encode_chunk(fingerprint, digest, i);
    if (encode_result != 0) {
      return -1;
    }
  }
  return 0;
}

int autograph_safety_number(unsigned char *safety_number,
                            const unsigned char *our_identity_key,
                            const unsigned char *their_identity_key) {
  unsigned char our_fingerprint[30];
  unsigned char their_fingerprint[30];
  int our_result = calculate_fingerprint(our_fingerprint, our_identity_key);
  int their_result =
      calculate_fingerprint(their_fingerprint, their_identity_key);
  if (our_result != 0 || their_result != 0) {
    return -1;
  }
  if (memcmp(our_fingerprint, their_fingerprint, 30) > 0) {
    memmove(safety_number, their_fingerprint, 30);
    memmove(safety_number + 30, our_fingerprint, 30);
  } else {
    memmove(safety_number, our_fingerprint, 30);
    memmove(safety_number + 30, their_fingerprint, 30);
  }
  return 0;
}
