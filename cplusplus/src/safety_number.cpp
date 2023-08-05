#include "safety_number.h"

#include "private.h"

namespace Autograph {

SafetyNumberFunction create_safety_number(const Bytes our_identity_key) {
  auto safety_number_function =
      [our_identity_key](const Bytes their_identity_key) {
        Bytes safety_number(60);
        bool success = autograph_safety_number(safety_number.data(),
                                               our_identity_key.data(),
                                               their_identity_key.data()) == 0;
        SafetyNumberResult result = {success, safety_number};
        return result;
      };
  return safety_number_function;
}

}  // namespace Autograph
