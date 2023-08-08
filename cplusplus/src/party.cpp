#include "party.h"

#include "private.h"
#include "sign.h"

namespace Autograph {

Party createParty(const bool isInitiator, const SignFunction sign,
                  const Bytes identityPublicKey) {
  auto calculateSafetyNumber = createSafetyNumber(identityPublicKey);
  auto performHandshake = createHandshake(isInitiator, sign, identityPublicKey);
  Party party = {
      calculateSafetyNumber,
      performHandshake,
  };
  return party;
}

Party createInitiator(const SignFunction sign, const Bytes identityPublicKey) {
  return createParty(true, sign, identityPublicKey);
}

Party createInitiator(const KeyPair identityKeyPair) {
  return createInitiator(createSign(identityKeyPair.privateKey),
                         identityKeyPair.publicKey);
}

Party createResponder(const SignFunction sign, const Bytes identityPublicKey) {
  return createParty(false, sign, identityPublicKey);
}

Party createResponder(const KeyPair identityKeyPair) {
  return createResponder(createSign(identityKeyPair.privateKey),
                         identityKeyPair.publicKey);
}

}  // namespace Autograph
