#include "sizes.h"

unsigned int autograph_ciphertext_size(unsigned int plaintext_size) {
  return plaintext_size + 16 - plaintext_size % 16 + 16;
}

unsigned int autograph_handshake_size() { return 96; }

unsigned int autograph_message_extra_size() { return 16; }

unsigned int autograph_plaintext_size(unsigned int ciphertext_size) {
  return ciphertext_size - 16;
}

unsigned int autograph_private_key_size() { return 32; }

unsigned int autograph_public_key_size() { return 32; }

unsigned int autograph_safety_number_size() { return 60; }

unsigned int autograph_secret_key_size() { return 32; }

unsigned int autograph_signature_size() { return 64; }

unsigned int autograph_transcript_size() { return 128; }
