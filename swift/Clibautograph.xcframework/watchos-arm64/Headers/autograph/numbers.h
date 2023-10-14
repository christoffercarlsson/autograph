#ifndef AUTOGRAPH_NUMBERS_H
#define AUTOGRAPH_NUMBERS_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned int autograph_read_uint32(const unsigned char *bytes);

unsigned long long autograph_read_uint64(const unsigned char *bytes);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
