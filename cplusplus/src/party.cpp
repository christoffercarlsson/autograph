#include "internal.h"

namespace autograph {

Party create_party(const bool is_initiator, const SignFunction sign,
                   const Bytes identity_public_key) {
  auto calculate_safety_number = create_safety_number(identity_public_key);
  auto perform_handshake =
      create_handshake(is_initiator, sign, identity_public_key);
  Party party = {
      calculate_safety_number,
      perform_handshake,
  };
  return party;
}

}  // namespace autograph
