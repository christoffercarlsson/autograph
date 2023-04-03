#include "autograph/safety_number.h"

#include "autograph/core/safety_number.h"

namespace autograph {

SafetyNumberFunction create_safety_number(
    const unsigned char *our_identity_key) {
  auto safety_number_function = [our_identity_key](
                                    unsigned char *safety_number,
                                    const unsigned char *their_identity_key) {
    int result = autograph_core_safety_number(safety_number, our_identity_key,
                                              their_identity_key);
    if (result != 0) {
      throw std::runtime_error("Failed to calculate safety number");
    }
  };
  return std::move(safety_number_function);
}

}  // namespace autograph
