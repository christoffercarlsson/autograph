#include <catch2/catch_test_macros.hpp>

#include "autograph.h"

TEST_CASE("Key pair", "[key_pair]") {
  Autograph::init();

  SECTION("should generate ephemeral key pairs") {
    auto result = Autograph::generateEphemeralKeyPair();
    REQUIRE(result.success == true);
    REQUIRE(result.keyPair.privateKey.size() == 32);
    REQUIRE(result.keyPair.publicKey.size() == 32);
  }

  SECTION("should generate identity key pairs") {
    auto result = Autograph::generateIdentityKeyPair();
    REQUIRE(result.success == true);
    REQUIRE(result.keyPair.privateKey.size() == 32);
    REQUIRE(result.keyPair.publicKey.size() == 32);
  }
}
