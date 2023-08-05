#ifndef AUTOGRAPH_PARTY_H
#define AUTOGRAPH_PARTY_H

#ifdef __cplusplus

#include "types.h"

namespace Autograph {

Party create_initiator(const SignFunction sign,
                       const Bytes identity_public_key);

Party create_initiator(const KeyPair identity_key_pair);

Party create_responder(const SignFunction sign,
                       const Bytes identity_public_key);

Party create_responder(const KeyPair identity_key_pair);

}  // namespace Autograph
#endif

#endif
