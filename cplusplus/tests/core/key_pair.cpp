#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Key Pair", "[core_key_pair]") {
  std::vector<unsigned char> empty_key(32);
  std::vector<unsigned char> private_key(32);
  std::vector<unsigned char> public_key(32);

  autograph_init();

  SECTION("should generate ephemeral key pairs") {
    int result =
        autograph_key_pair_ephemeral(private_key.data(), public_key.data());
    REQUIRE(result == 0);
    REQUIRE_THAT(private_key, !Catch::Matchers::Equals(empty_key));
    REQUIRE_THAT(public_key, !Catch::Matchers::Equals(empty_key));
  }

  SECTION("should generate identity key pairs") {
    int result =
        autograph_key_pair_identity(private_key.data(), public_key.data());
    REQUIRE(result == 0);
    REQUIRE_THAT(private_key, !Catch::Matchers::Equals(empty_key));
    REQUIRE_THAT(public_key, !Catch::Matchers::Equals(empty_key));
  }
}
