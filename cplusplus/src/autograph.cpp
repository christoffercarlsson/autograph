#include "autograph.hpp"

#include "autograph.h"
#include "private.hpp"

namespace autograph {

Party create_initiator(const unsigned char *identity_private_key,
                       const unsigned char *identity_public_key,
                       unsigned char *ephemeral_private_key,
                       const unsigned char *ephemeral_public_key) {
  auto party = create_party(true, identity_private_key, identity_public_key,
                            ephemeral_private_key, ephemeral_public_key);
  return std::move(party);
}

Party create_responder(const unsigned char *identity_private_key,
                       const unsigned char *identity_public_key,
                       unsigned char *ephemeral_private_key,
                       const unsigned char *ephemeral_public_key) {
  auto party = create_party(false, identity_private_key, identity_public_key,
                            ephemeral_private_key, ephemeral_public_key);
  return std::move(party);
}

bool generate_ephemeral_key_pair(unsigned char *private_key,
                                 unsigned char *public_key) {
  return autograph_key_pair_ephemeral(private_key, public_key) == 0;
}

bool generate_identity_key_pair(unsigned char *private_key,
                                unsigned char *public_key) {
  return autograph_key_pair_identity(private_key, public_key) == 0;
}

bool init() { return autograph_init() == 0; }

}  // namespace autograph
