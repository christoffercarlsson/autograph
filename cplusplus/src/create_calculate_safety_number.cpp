#include "autograph/create_calculate_safety_number.h"

#include <algorithm>
#include <string>

#include "autograph/calculate_safety_number.h"
#include "autograph/constants.h"

CalculateSafetyNumberFunction create_calculate_safety_number(
    const Chunk &our_identity_key) {
  auto calculate_safety_number_function =
      [&our_identity_key](const Chunk &their_identity_key) {
        Chunk safety_number(SAFETY_NUMBER_SIZE);
        bool success = calculate_safety_number(safety_number.data(),
                                               our_identity_key.data(),
                                               their_identity_key.data());
        if (!success) {
          throw std::runtime_error("Failed to calculate safety number");
        }
        return std::move(safety_number);
      };
  return std::move(calculate_safety_number_function);
}
