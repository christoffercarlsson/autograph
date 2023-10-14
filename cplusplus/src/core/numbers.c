#include "numbers.h"

unsigned long long autograph_read_uint(const unsigned char *bytes,
                                       const unsigned char size) {
  unsigned long long number = 0;
  for (unsigned int i = 0; i < size; i++) {
    number = (number << 8) | bytes[i];
  }
  return number;
}

unsigned int autograph_read_uint32(const unsigned char *bytes) {
  return (unsigned int)autograph_read_uint(bytes, 4);
}

unsigned long long autograph_read_uint64(const unsigned char *bytes) {
  return autograph_read_uint(bytes, 8);
}
