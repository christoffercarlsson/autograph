#include "autograph/init.h"

void init() {
  if (sodium_init() != 0) {
    throw std::runtime_error("Failed to initialize libsodium");
  }
}
