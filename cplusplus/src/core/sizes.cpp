#include "autograph.h"
#include "constants.hpp"

unsigned int autograph_handshake_size() { return autograph::HANDSHAKE_SIZE; }

unsigned int autograph_message_extra_size() {
  return autograph::MESSAGE_EXTRA_SIZE;
}

unsigned int autograph_private_key_size() {
  return autograph::PRIVATE_KEY_SIZE;
}

unsigned int autograph_public_key_size() { return autograph::PUBLIC_KEY_SIZE; }

unsigned int autograph_secret_key_size() { return autograph::SECRET_KEY_SIZE; }

unsigned int autograph_safety_number_size() {
  return autograph::SAFETY_NUMBER_SIZE;
}

unsigned int autograph_signature_size() { return autograph::SIGNATURE_SIZE; }

unsigned int autograph_transcript_size() { return autograph::TRANSCRIPT_SIZE; }
