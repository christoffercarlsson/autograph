#include "autograph/party.h"

#include "autograph/handshake.h"
#include "autograph/safety_number.h"

namespace autograph {

void generate_ephemeral_key_pair(unsigned char* private_key,
                                 unsigned char* public_key) {
  int result = autograph_core_key_pair_ephemeral(private_key, public_key);
  if (result != 0) {
    throw std::runtime_error("Failed to generate ephemeral key pair");
  }
}

Party create_party(unsigned char* ephemeral_public_key, bool is_initiator,
                   const unsigned char* identity_private_key,
                   const unsigned char* identity_public_key) {
  PrivateKey ephemeral_private_key;
  generate_ephemeral_key_pair(ephemeral_private_key, ephemeral_public_key);
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
