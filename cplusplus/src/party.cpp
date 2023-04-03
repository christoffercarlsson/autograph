#include "private.hpp"

namespace autograph {

Party create_party(bool is_initiator, const unsigned char *identity_private_key,
                   const unsigned char *identity_public_key,
                   unsigned char *ephemeral_private_key,
                   const unsigned char *ephemeral_public_key) {
  auto calculate_safety_number = create_safety_number(identity_public_key);
  auto perform_handshake =
      create_handshake(is_initiator, identity_private_key, identity_public_key,
                       ephemeral_private_key, ephemeral_public_key);
  Party party = {
      calculate_safety_number,
      perform_handshake,
  };
  return std::move(party);
}

}  // namespace autograph
