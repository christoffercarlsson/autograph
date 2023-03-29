#include "autograph/party.h"

#include "autograph/handshake.h"
#include "autograph/key_pair.h"
#include "autograph/safety_number.h"

namespace autograph {

Party party_create(bool is_initiator, const KeyPair &identity_key_pair) {
  auto ephemeral_key_pair = key_pair_ephemeral();
  auto calculate_safety_number =
      safety_number_create(identity_key_pair.public_key);
  auto perform_handshake = handshake_create(is_initiator, identity_key_pair,
                                            ephemeral_key_pair.private_key,
                                            ephemeral_key_pair.public_key);
  Party party = {
      calculate_safety_number,
      ephemeral_key_pair.public_key,
      perform_handshake,
      identity_key_pair.public_key,
  };
  return std::move(party);
}

}  // namespace autograph
