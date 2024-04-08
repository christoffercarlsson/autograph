#include "autograph.h"

namespace Autograph {

tuple<bool, SafetyNumber> authenticate(const KeyPair &ourIdentityKeyPair,
                                       const PublicKey &theirIdentityKey) {
  SafetyNumber safetyNumber;
  bool success = autograph_authenticate(
      safetyNumber.data(), ourIdentityKeyPair.data(), theirIdentityKey.data());
  return make_tuple(success, safetyNumber);
}

}  // namespace Autograph
