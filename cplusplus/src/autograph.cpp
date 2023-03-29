#include "autograph.h"

#include "autograph/core/init.h"
#include "autograph/key_pair.h"
#include "autograph/party.h"

namespace autograph {

Party create_initiator(const KeyPair &identity_key_pair) {
  auto party = create_party(true, identity_key_pair);
  return std::move(party);
}

Party create_responder(const KeyPair &identity_key_pair) {
  auto party = create_party(false, identity_key_pair);
  return std::move(party);
}

void init() {
  int result = autograph_core_init();
  if (result != 0) {
    throw std::runtime_error("Failed to initialize Autograph");
  }
}

KeyPair generate_key_pair() {
  auto key_pair = generate_identity_key_pair();
  return std::move(key_pair);
}

}  // namespace autograph
