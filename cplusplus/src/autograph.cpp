#include "autograph.h"

#include "autograph/core/init.h"
#include "autograph/key_pair.h"
#include "autograph/party.h"

namespace autograph {

Party create_initiator(const KeyPair &identity_key_pair) {
  auto party = party_create(true, identity_key_pair);
  return std::move(party);
}

Party create_responder(const KeyPair &identity_key_pair) {
  auto party = party_create(false, identity_key_pair);
  return std::move(party);
}

void init() {
  bool success = autograph_core_init();
  if (!success) {
    throw std::runtime_error("Failed to initialize Autograph");
  }
}

KeyPair generate_key_pair() {
  auto keys = key_pair_identity();
  return std::move(keys);
}

}  // namespace autograph
