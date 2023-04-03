#include "autograph.h"
#include "private.hpp"

namespace autograph {

SafetyNumberFunction create_safety_number(
    const unsigned char *our_identity_key) {
  auto safety_number_function = [our_identity_key](
                                    unsigned char *safety_number,
                                    const unsigned char *their_identity_key) {
    return autograph_safety_number(safety_number, our_identity_key,
                                   their_identity_key) == 0;
  };
  return std::move(safety_number_function);
}

}  // namespace autograph
