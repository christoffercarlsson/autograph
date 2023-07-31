#ifndef AUTOGRAPH_SIZES_H
#define AUTOGRAPH_SIZES_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned int autograph_handshake_size();

unsigned int autograph_message_extra_size();

unsigned int autograph_private_key_size();

unsigned int autograph_public_key_size();

unsigned int autograph_safety_number_size();

unsigned int autograph_secret_key_size();

unsigned int autograph_signature_size();

unsigned int autograph_transcript_size();

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
