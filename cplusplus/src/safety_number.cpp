#include "safety_number.h"

#include "private.h"

namespace Autograph {

SafetyNumberFunction createSafetyNumber(const Bytes ourIdentityKey) {
  auto safetyNumberFunction = [ourIdentityKey](const Bytes theirIdentityKey) {
    Bytes safetyNumber(60);
    bool success =
        autograph_safety_number(safetyNumber.data(), ourIdentityKey.data(),
                                theirIdentityKey.data()) == 0;
    SafetyNumberResult result = {success, safetyNumber};
    return result;
  };
  return safetyNumberFunction;
}

}  // namespace Autograph
