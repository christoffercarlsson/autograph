#include "autograph/core/init.h"

#include "sodium.h"

int autograph_core_init() {
  if (sodium_init() == 0 && crypto_aead_aes256gcm_is_available() == 1) {
    return 0;
  } else {
    return -1;
  }
}
