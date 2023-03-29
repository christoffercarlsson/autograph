#include "autograph/core/init.h"

#include "sodium.h"

bool autograph_core_init() {
  return sodium_init() == 0 && crypto_aead_aes256gcm_is_available() == 1;
}
