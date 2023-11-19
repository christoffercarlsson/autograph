#include <catch2/catch_test_macros.hpp>

#include "autograph.h"

TEST_CASE("Data sizes", "[core_sizes]") {
  SECTION("should return the correct ciphertext size") {
    REQUIRE(autograph_ciphertext_size(11) == 32);
    REQUIRE(autograph_ciphertext_size(16) == 48);
  }

  SECTION("should return the correct handshake size") {
    REQUIRE(autograph_handshake_size() == 96);
    REQUIRE(Autograph::HANDSHAKE_SIZE == 96);
  }

  SECTION("should return the correct index size") {
    REQUIRE(autograph_index_size() == 8);
    REQUIRE(Autograph::INDEX_SIZE == 8);
  }

  SECTION("should return the correct plaintext size") {
    REQUIRE(autograph_plaintext_size(32) == 16);
    REQUIRE(autograph_plaintext_size(64) == 48);
  }

  SECTION("should return the correct private key size") {
    REQUIRE(autograph_private_key_size() == 32);
    REQUIRE(Autograph::PRIVATE_KEY_SIZE == 32);
  }

  SECTION("should return the correct public key size") {
    REQUIRE(autograph_public_key_size() == 32);
    REQUIRE(Autograph::PUBLIC_KEY_SIZE == 32);
  }

  SECTION("should return the correct safety number size") {
    REQUIRE(autograph_safety_number_size() == 60);
    REQUIRE(Autograph::SAFETY_NUMBER_SIZE == 60);
  }

  SECTION("should return the correct secret key size") {
    REQUIRE(autograph_secret_key_size() == 32);
    REQUIRE(Autograph::SECRET_KEY_SIZE == 32);
  }

  SECTION("should return the correct signature size") {
    REQUIRE(autograph_signature_size() == 64);
    REQUIRE(Autograph::SIGNATURE_SIZE == 64);
  }

  SECTION("should return the correct size size") {
    REQUIRE(autograph_size_size() == 4);
    REQUIRE(Autograph::SIZE_SIZE == 4);
  }

  SECTION("should return the correct skipped keys size") {
    REQUIRE(autograph_skipped_keys_size() == 40002);
    REQUIRE(Autograph::SKIPPED_KEYS_SIZE == 40002);
  }

  SECTION("should return the correct subject size") {
    REQUIRE(autograph_subject_size(3) == 35);
  }

  SECTION("should return the correct transcript size") {
    REQUIRE(autograph_transcript_size() == 128);
    REQUIRE(Autograph::TRANSCRIPT_SIZE == 128);
  }
}
