#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Numbers", "[core_numbers]") {
  std::vector<unsigned char> a = {1, 2, 3, 4};
  std::vector<unsigned char> b = {1, 2, 3, 4, 5, 6, 7, 8};

  unsigned int c = autograph_read_uint32(a.data());
  unsigned long long d = autograph_read_uint64(b.data());

  REQUIRE(c == 16909060);
  REQUIRE(d == 72623859790382856);
}
