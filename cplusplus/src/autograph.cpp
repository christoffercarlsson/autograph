#include "autograph.h"

#include "autograph/core/init.h"
#include "autograph/core/key_pair.h"
#include "autograph/party.h"

namespace autograph {

Party create_initiator(unsigned char* ephemeral_public_key,
                       const unsigned char* private_key,
                       const unsigned char* public_key) {
  auto party =
      create_party(ephemeral_public_key, true, private_key, public_key);
  return std::move(party);
}

Party create_responder(unsigned char* ephemeral_public_key,
                       const unsigned char* private_key,
                       const unsigned char* public_key) {
  auto party =
      create_party(ephemeral_public_key, false, private_key, public_key);
  return std::move(party);
}

void init() {
  int result = autograph_core_init();
  if (result != 0) {
    throw std::runtime_error("Failed to initialize Autograph");
  }
}

void generate_key_pair(unsigned char* private_key, unsigned char* public_key) {
  int result = autograph_core_key_pair_identity(private_key, public_key);
  if (result != 0) {
    throw std::runtime_error("Failed to generate identity key pair");
  }
}

}  // namespace autograph
