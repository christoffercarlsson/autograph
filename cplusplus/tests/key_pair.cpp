#include <catch2/catch_test_macros.hpp>

#include "autograph.hpp"

TEST_CASE("Key Pair", "[key_pair]") {
  autograph::init();

  SECTION("should generate ephemeral key pairs") {
    auto key_pair = autograph::generate_ephemeral_key_pair();
    REQUIRE(key_pair.private_key.size() == 32);
    REQUIRE(key_pair.public_key.size() == 32);
  }

  SECTION("should generate identity key pairs") {
    auto key_pair = autograph::generate_identity_key_pair();
    REQUIRE(key_pair.private_key.size() == 32);
    REQUIRE(key_pair.public_key.size() == 32);
  }
}
