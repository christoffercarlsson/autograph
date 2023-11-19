#ifndef AUTOGRAPH_SIZES_H
#define AUTOGRAPH_SIZES_H

#ifdef __cplusplus
extern "C" {
#endif

unsigned int autograph_ciphertext_size(unsigned int plaintext_size);

unsigned int autograph_handshake_size();

unsigned int autograph_index_size();

unsigned int autograph_plaintext_size(unsigned int ciphertext_size);

unsigned int autograph_private_key_size();

unsigned int autograph_public_key_size();

unsigned int autograph_safety_number_size();

unsigned int autograph_secret_key_size();

unsigned int autograph_signature_size();

unsigned int autograph_size_size();

unsigned int autograph_skipped_keys_size();

unsigned int autograph_subject_size(unsigned int size);

unsigned int autograph_transcript_size();

#ifdef __cplusplus
}  // extern "C"

namespace Autograph {

const unsigned int HANDSHAKE_SIZE = 96;

const unsigned int INDEX_SIZE = 8;

const unsigned int PRIVATE_KEY_SIZE = 32;

const unsigned int PUBLIC_KEY_SIZE = 32;

const unsigned int SAFETY_NUMBER_SIZE = 60;

const unsigned int SECRET_KEY_SIZE = 32;

const unsigned int SIGNATURE_SIZE = 64;

const unsigned int SIZE_SIZE = 4;

const unsigned int SKIPPED_KEYS_SIZE = 40002;

const unsigned int TRANSCRIPT_SIZE = 128;

}  // namespace Autograph
#endif

#endif
