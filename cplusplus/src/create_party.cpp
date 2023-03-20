#include "autograph/create_party.h"

Party create_party(bool is_initiator, const KeyPair &identity_key_pair) {
  KeyPair ephemeral_key_pair = generate_ephemeral_key_pair();
  CalculateSafetyNumberFunction calculate_safety_number =
      create_calculate_safety_number(identity_key_pair.public_key);
  HandshakeFunction handshake =
      create_handshake(is_initiator, identity_key_pair, ephemeral_key_pair);
  Party party = {
      calculate_safety_number,
      ephemeral_key_pair.public_key,
      handshake,
      identity_key_pair.public_key,
  };
  return std::move(party);
}
