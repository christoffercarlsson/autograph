#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Ownership", "[core_ownership]") {
  std::vector<unsigned char> alicePublicKey = {
      91, 119, 85, 151, 32,  20, 121, 20, 19,  106, 90,  56,  141, 90,  16, 210,
      14, 244, 60, 251, 140, 48, 190, 65, 194, 35,  166, 246, 1,   209, 4,  33};

  std::vector<unsigned char> data = {72, 101, 108, 108, 111, 32,
                                     87, 111, 114, 108, 100};

  std::vector<unsigned char> aliceCertificate = {
      123, 223, 90,  28,  163, 65,  187, 199, 14,  78,  92,  116, 38,  48,
      178, 123, 72,  213, 94,  252, 250, 127, 184, 0,   187, 249, 157, 102,
      227, 241, 114, 20,  82,  239, 167, 88,  84,  82,  16,  198, 184, 193,
      35,  9,   78,  135, 162, 198, 47,  53,  179, 3,   242, 165, 38,  18,
      209, 74,  113, 86,  99,  124, 196, 124, 75,  99,  159, 106, 233, 232,
      188, 251, 194, 157, 166, 7,   134, 203, 32,  253, 65,  90,  40,  91,
      76,  25,  252, 156, 139, 154, 148, 183, 71,  7,   109, 5};

  std::vector<unsigned char> bobPrivateKey = {
      243, 11,  156, 139, 99,  129, 212, 8,   60,  53, 111,
      123, 69,  158, 83,  255, 187, 192, 29,  114, 69, 126,
      243, 111, 122, 143, 170, 247, 140, 129, 60,  0};

  std::vector<unsigned char> bobSignature = {
      188, 36,  195, 130, 177, 84,  21,  74,  125, 139, 109, 135, 207,
      42,  213, 11,  153, 158, 183, 160, 112, 141, 216, 204, 167, 194,
      159, 123, 221, 162, 50,  220, 49,  54,  123, 73,  132, 73,  15,
      144, 65,  252, 249, 192, 145, 159, 22,  224, 143, 25,  226, 32,
      54,  44,  139, 196, 85,  254, 198, 61,  138, 244, 223, 4};

  autograph_init();

  SECTION(
      "should allow Bob to certify Alice's ownership of her identity key and "
      "data") {
    std::vector<unsigned char> signature(64);
    int result =
        autograph_certify(signature.data(), bobPrivateKey.data(),
                          alicePublicKey.data(), data.data(), data.size());

    REQUIRE(result == 0);
    REQUIRE_THAT(signature, Catch::Matchers::Equals(bobSignature));
  }

  SECTION(
      "should allow Bob to verify Alice's ownership of her identity key and "
      "data based on Charlie's public key and signature") {
    int result =
        autograph_verify(alicePublicKey.data(), aliceCertificate.data(), 1,
                         data.data(), data.size());

    REQUIRE(result == 0);
  }
}
