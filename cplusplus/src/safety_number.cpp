#include "safety_number.h"

#include "error.h"
#include "init.h"
#include "sizes.h"

namespace Autograph {

std::vector<unsigned char> calculateSafetyNumber(std::vector<unsigned char> a,
                                                 std::vector<unsigned char> b) {
  if (autograph_init() != 0) {
    throw Error(Error::Initialization);
  }
  std::vector<unsigned char> safetyNumber(SAFETY_NUMBER_SIZE);
  bool success =
      autograph_safety_number(safetyNumber.data(), a.data(), b.data()) == 0;
  if (!success) {
    throw Error(Error::SafetyNumberCalculation);
  }
  return safetyNumber;
}

}  // namespace Autograph
