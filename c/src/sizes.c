#include "autograph.h"

unsigned int autograph_handshake_size() { return 80; }

unsigned int autograph_message_extra_size() { return 20; }

unsigned int autograph_private_key_size() { return 32; }

unsigned int autograph_public_key_size() { return 32; }

unsigned int autograph_secret_key_size() { return 32; }

unsigned int autograph_safety_number_size() { return 60; }

unsigned int autograph_signature_size() { return 64; }

unsigned int autograph_transcript_size() { return 128; }
