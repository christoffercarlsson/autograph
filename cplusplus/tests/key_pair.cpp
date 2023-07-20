#include <catch2/catch_test_macros.hpp>

#include "autograph.h"

TEST_CASE("Key Pair", "[key_pair]") {
  autograph::init();

  SECTION("should generate ephemeral key pairs") {
    auto result = autograph::generate_ephemeral_key_pair();
    REQUIRE(result.success == true);
    REQUIRE(result.key_pair.private_key.size() == 32);
    REQUIRE(result.key_pair.public_key.size() == 32);
  }

  SECTION("should generate identity key pairs") {
    auto result = autograph::generate_identity_key_pair();
    REQUIRE(result.success == true);
    REQUIRE(result.key_pair.private_key.size() == 32);
    REQUIRE(result.key_pair.public_key.size() == 32);
  }
}
