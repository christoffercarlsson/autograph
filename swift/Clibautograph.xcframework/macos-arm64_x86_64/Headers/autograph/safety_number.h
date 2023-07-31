#ifndef AUTOGRAPH_SAFETY_NUMBER_H
#define AUTOGRAPH_SAFETY_NUMBER_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_safety_number(unsigned char *safety_number,
                            const unsigned char *our_identity_key,
                            const unsigned char *their_identity_key);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
