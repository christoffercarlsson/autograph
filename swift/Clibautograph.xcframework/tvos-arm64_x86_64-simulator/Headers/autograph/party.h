#ifndef AUTOGRAPH_PARTY_H
#define AUTOGRAPH_PARTY_H

#ifdef __cplusplus

#include "types.h"

namespace Autograph {

Party createInitiator(const SignFunction sign, const Bytes identityPublicKey);

Party createInitiator(const KeyPair identityKeyPair);

Party createResponder(const SignFunction sign, const Bytes identityPublicKey);

Party createResponder(const KeyPair identityKeyPair);

}  // namespace Autograph
#endif

#endif
