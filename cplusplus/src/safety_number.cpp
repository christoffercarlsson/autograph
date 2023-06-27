#include "internal.h"

namespace autograph {

SafetyNumberFunction create_safety_number(const Bytes our_identity_key) {
  auto safety_number_function =
      [our_identity_key](const Bytes their_identity_key) {
        Bytes safety_number(60);
        int result = autograph_safety_number(safety_number.data(),
                                             our_identity_key.data(),
                                             their_identity_key.data());
        if (result != 0) {
          throw std::runtime_error("Safety number calculation failed");
        }
        return safety_number;
      };
  return safety_number_function;
}

}  // namespace autograph
