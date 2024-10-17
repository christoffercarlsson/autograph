#include <catch2/catch_test_macros.hpp>

#include "autograph.h"

TEST_CASE("Key pair", "[key_pair]") {
  Autograph::Bytes emptyKeyPair(64);

  bool initialized = Autograph::ready();
  REQUIRE(initialized == true);

  SECTION("should generate identity key pairs") {
    auto [success, keyPair] = Autograph::generateIdentityKeyPair();
    REQUIRE(success == true);
    REQUIRE(keyPair != emptyKeyPair);
  }

  SECTION("should generate session key pairs") {
    auto [success, keyPair] = Autograph::generateSessionKeyPair();
    REQUIRE(success == true);
    REQUIRE(keyPair != emptyKeyPair);
  }
}
