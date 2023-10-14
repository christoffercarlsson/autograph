#include <catch2/catch_test_macros.hpp>

#include "autograph.h"

TEST_CASE("Data sizes", "[core_sizes]") {
  SECTION("should return the correct ciphertext size") {
    REQUIRE(autograph_ciphertext_size(11) == 32);
    REQUIRE(autograph_ciphertext_size(16) == 48);
  }

  SECTION("should return the correct handshake size") {
    REQUIRE(autograph_handshake_size() == 96);
  }

  SECTION("should return the correct message extra size") {
    REQUIRE(autograph_message_extra_size() == 16);
  }

  SECTION("should return the correct plaintext size") {
    REQUIRE(autograph_plaintext_size(32) == 16);
    REQUIRE(autograph_plaintext_size(64) == 48);
  }

  SECTION("should return the correct private key size") {
    REQUIRE(autograph_private_key_size() == 32);
  }

  SECTION("should return the correct public key size") {
    REQUIRE(autograph_public_key_size() == 32);
  }

  SECTION("should return the correct safety number size") {
    REQUIRE(autograph_safety_number_size() == 60);
  }

  SECTION("should return the correct secret key size") {
    REQUIRE(autograph_secret_key_size() == 32);
  }

  SECTION("should return the correct signature size") {
    REQUIRE(autograph_signature_size() == 64);
  }

  SECTION("should return the correct transcript size") {
    REQUIRE(autograph_transcript_size() == 128);
  }
}
