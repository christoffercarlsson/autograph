#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Safety number", "[core_safety_number]") {
  std::vector<unsigned char> aliceIdentityKey = {
      91, 119, 85, 151, 32,  20, 121, 20, 19,  106, 90,  56,  141, 90,  16, 210,
      14, 244, 60, 251, 140, 48, 190, 65, 194, 35,  166, 246, 1,   209, 4,  33};

  std::vector<unsigned char> bobIdentityKey = {
      232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235,
      97,  118, 3,   241, 131, 200, 140, 54,  155, 28,  46,
      158, 76,  96,  4,   150, 61,  34,  13,  133, 138};

  std::vector<unsigned char> safetyNumber = {
      52, 52, 57, 52, 50, 50, 53, 55, 54, 50, 48, 53, 51, 51, 49,
      55, 56, 54, 48, 50, 55, 53, 56, 48, 54, 52, 56, 52, 53, 49,
      53, 55, 50, 49, 50, 54, 49, 50, 50, 49, 57, 52, 53, 57, 52,
      50, 55, 54, 49, 49, 54, 49, 57, 50, 52, 53, 52, 57, 50, 54};

  std::vector<unsigned char> aliceSafetyNumber(60);
  std::vector<unsigned char> bobSafetyNumber(60);

  autograph_init();

  int alice_result = autograph_safety_number(
      aliceSafetyNumber.data(), aliceIdentityKey.data(), bobIdentityKey.data());
  int bob_result = autograph_safety_number(
      bobSafetyNumber.data(), bobIdentityKey.data(), aliceIdentityKey.data());

  REQUIRE(alice_result == 0);
  REQUIRE(bob_result == 0);
  REQUIRE_THAT(aliceSafetyNumber, Catch::Matchers::Equals(safetyNumber));
  REQUIRE_THAT(bobSafetyNumber, Catch::Matchers::Equals(safetyNumber));
}
