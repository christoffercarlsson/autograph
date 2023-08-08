#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Key Pair", "[core_key_pair]") {
  std::vector<unsigned char> emptyKey(32);
  std::vector<unsigned char> privateKey(32);
  std::vector<unsigned char> publicKey(32);

  autograph_init();

  SECTION("should generate ephemeral key pairs") {
    int result =
        autograph_key_pair_ephemeral(privateKey.data(), publicKey.data());
    REQUIRE(result == 0);
    REQUIRE_THAT(privateKey, !Catch::Matchers::Equals(emptyKey));
    REQUIRE_THAT(publicKey, !Catch::Matchers::Equals(emptyKey));
  }

  SECTION("should generate identity key pairs") {
    int result =
        autograph_key_pair_identity(privateKey.data(), publicKey.data());
    REQUIRE(result == 0);
    REQUIRE_THAT(privateKey, !Catch::Matchers::Equals(emptyKey));
    REQUIRE_THAT(publicKey, !Catch::Matchers::Equals(emptyKey));
  }
}
