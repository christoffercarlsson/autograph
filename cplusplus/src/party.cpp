#include "internal.h"

namespace autograph {

Party create_party(const bool is_initiator, const KeyPair identity_key_pair,
                   KeyPair ephemeral_key_pair) {
  auto calculate_safety_number =
      create_safety_number(identity_key_pair.public_key);
  auto perform_handshake =
      create_handshake(is_initiator, identity_key_pair, ephemeral_key_pair);
  Party party = {
      calculate_safety_number,
      perform_handshake,
  };
  return party;
}

}  // namespace autograph
