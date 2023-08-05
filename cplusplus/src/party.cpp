#include "party.h"

#include "private.h"
#include "sign.h"

namespace Autograph {

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

Party create_initiator(const SignFunction sign,
                       const Bytes identity_public_key) {
  return create_party(true, sign, identity_public_key);
}

Party create_initiator(const KeyPair identity_key_pair) {
  return create_initiator(create_sign(identity_key_pair.private_key),
                          identity_key_pair.public_key);
}

Party create_responder(const SignFunction sign,
                       const Bytes identity_public_key) {
  return create_party(false, sign, identity_public_key);
}

Party create_responder(const KeyPair identity_key_pair) {
  return create_responder(create_sign(identity_key_pair.private_key),
                          identity_key_pair.public_key);
}

}  // namespace Autograph
