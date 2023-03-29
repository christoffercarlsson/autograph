#include "autograph/safety_number.h"

#include "autograph/core/safety_number.h"

namespace autograph {

SafetyNumberFunction safety_number_create(const Chunk &our_identity_key) {
  auto safety_number_function =
      [&our_identity_key](const Chunk &their_identity_key) {
        Chunk safety_number(autograph_core_safety_number_SIZE);
        int result = autograph_core_safety_number(safety_number.data(),
                                                  our_identity_key.data(),
                                                  their_identity_key.data());
        if (result != 0) {
          throw std::runtime_error("Failed to calculate safety number");
        }
        return std::move(safety_number);
      };
  return std::move(safety_number_function);
}

}  // namespace autograph
