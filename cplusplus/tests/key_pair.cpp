#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Key pair", "[key_pair]") {
  std::vector<unsigned char> emptyKey(32);

  SECTION("should generate ephemeral key pairs") {
    auto keyPair = Autograph::generateEphemeralKeyPair();
    REQUIRE(keyPair.privateKey.size() == 32);
    REQUIRE(keyPair.publicKey.size() == 32);
    REQUIRE_THAT(keyPair.privateKey, !Catch::Matchers::Equals(emptyKey));
    REQUIRE_THAT(keyPair.publicKey, !Catch::Matchers::Equals(emptyKey));
  }

  SECTION("should generate identity key pairs") {
    auto keyPair = Autograph::generateIdentityKeyPair();
    REQUIRE(keyPair.privateKey.size() == 32);
    REQUIRE(keyPair.publicKey.size() == 32);
    REQUIRE_THAT(keyPair.privateKey, !Catch::Matchers::Equals(emptyKey));
    REQUIRE_THAT(keyPair.publicKey, !Catch::Matchers::Equals(emptyKey));
  }
}
