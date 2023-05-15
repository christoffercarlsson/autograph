#include <catch2/catch_test_macros.hpp>

#include "autograph.h"

TEST_CASE("Initialization", "[core_init]") {
  int result = autograph_init();
  REQUIRE(result == 0);
}
