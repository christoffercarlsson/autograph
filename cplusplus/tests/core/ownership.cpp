#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Ownership", "[core_ownership]") {
  std::vector<unsigned char> alice_public_key = {
      91, 119, 85, 151, 32,  20, 121, 20, 19,  106, 90,  56,  141, 90,  16, 210,
      14, 244, 60, 251, 140, 48, 190, 65, 194, 35,  166, 246, 1,   209, 4,  33};

  std::vector<unsigned char> alice_secret_key = {
      204, 150, 53,  221, 135, 13,  190, 124, 249, 0,   114,
      60,  155, 58,  196, 204, 106, 115, 64,  123, 101, 116,
      92,  214, 170, 19,  239, 225, 138, 163, 113, 129};

  std::vector<unsigned char> alice_message = {
      0,   0,   0,   1,   203, 203, 240, 117, 151, 142, 77,
      113, 252, 151, 171, 12,  154, 177, 105, 6,   248, 79,
      37,  105, 238, 243, 135, 194, 50,  34,  253};

  std::vector<unsigned char> alice_certificate = {
      232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235, 97,  118, 3,
      241, 131, 200, 140, 54,  155, 28,  46,  158, 76,  96,  4,   150, 61,
      34,  13,  133, 138, 188, 36,  195, 130, 177, 84,  21,  74,  125, 139,
      109, 135, 207, 42,  213, 11,  153, 158, 183, 160, 112, 141, 216, 204,
      167, 194, 159, 123, 221, 162, 50,  220, 49,  54,  123, 73,  132, 73,
      15,  144, 65,  252, 249, 192, 145, 159, 22,  224, 143, 25,  226, 32,
      54,  44,  139, 196, 85,  254, 198, 61,  138, 244, 223, 4};

  std::vector<unsigned char> bob_private_key = {
      243, 11,  156, 139, 99,  129, 212, 8,   60,  53, 111,
      123, 69,  158, 83,  255, 187, 192, 29,  114, 69, 126,
      243, 111, 122, 143, 170, 247, 140, 129, 60,  0};

  std::vector<unsigned char> bob_signature = {
      173, 114, 114, 160, 51,  91,  40,  39,  223, 144, 168, 53,  94,
      199, 250, 184, 88,  132, 31,  232, 50,  177, 147, 144, 102, 146,
      120, 27,  57,  63,  60,  151, 237, 224, 85,  65,  200, 38,  227,
      34,  88,  131, 168, 236, 107, 4,   200, 54,  232, 176, 16,  44,
      144, 106, 77,  28,  246, 104, 17,  77,  150, 92,  116, 0};

  std::vector<unsigned char> signature(64);

  autograph_init();

  int certify_result = autograph_certify(
      signature.data(), bob_private_key.data(), alice_public_key.data(),
      alice_secret_key.data(), NULL, 0);

  std::vector<unsigned char> certificate;
  certificate.insert(certificate.end(), alice_public_key.begin(),
                     alice_public_key.end());
  certificate.insert(certificate.end(), signature.begin(), signature.end());

  int verify_result = autograph_verify(
      alice_public_key.data(), alice_secret_key.data(), certificate.data(), 1,
      alice_message.data(), alice_message.size());

  REQUIRE(certify_result == 0);
  REQUIRE(verify_result == 0);
  REQUIRE_THAT(signature, Catch::Matchers::Equals(bob_signature));
  REQUIRE_THAT(certificate, Catch::Matchers::Equals(alice_certificate));
}
