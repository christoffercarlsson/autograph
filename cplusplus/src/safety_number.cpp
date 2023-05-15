#include "autograph.h"
#include "private.hpp"

namespace autograph {

SafetyNumberFunction create_safety_number(const Bytes &our_identity_key) {
  auto safety_number_function =
      [&our_identity_key](const Bytes &their_identity_key) {
        Bytes safety_number(SAFETY_NUMBER_SIZE);
        bool success = autograph_safety_number(safety_number.data(),
                                               our_identity_key.data(),
                                               their_identity_key.data()) == 0;
        if (!success) {
          throw std::runtime_error("Safety number calculation failed");
        }
        return std::move(safety_number);
      };
  return std::move(safety_number_function);
}

}  // namespace autograph
