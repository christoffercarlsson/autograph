#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Key exchange", "[core_key_exchange]") {
  std::vector<unsigned char> alicePrivateIdentityKey = {
      43, 6,  246, 172, 137, 170, 33,  12, 118, 177, 111, 60, 19, 37, 65, 122,
      28, 34, 200, 251, 96,  35,  187, 52, 74,  224, 143, 39, 90, 51, 33, 140};

  std::vector<unsigned char> alicePublicIdentityKey = {
      91, 119, 85, 151, 32,  20, 121, 20, 19,  106, 90,  56,  141, 90,  16, 210,
      14, 244, 60, 251, 140, 48, 190, 65, 194, 35,  166, 246, 1,   209, 4,  33};

  std::vector<unsigned char> alicePrivateEphemeralKey = {
      171, 243, 152, 144, 76,  145, 84,  13,  243, 173, 102,
      244, 84,  223, 43,  104, 182, 128, 230, 247, 121, 221,
      222, 203, 10,  80,  43,  88,  177, 155, 1,   114};

  std::vector<unsigned char> alicePublicEphemeralKey = {
      16,  9,   47,  109, 23,  19,  165, 137, 95,  186, 203,
      186, 154, 179, 116, 3,   160, 119, 225, 180, 226, 19,
      172, 45,  113, 125, 124, 86,  94,  159, 161, 119};

  std::vector<unsigned char> bobPublicIdentityKey = {
      232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235,
      97,  118, 3,   241, 131, 200, 140, 54,  155, 28,  46,
      158, 76,  96,  4,   150, 61,  34,  13,  133, 138};

  std::vector<unsigned char> bobPublicEphemeralKey = {
      249, 212, 82,  190, 253, 45,  230, 86,  74,  150, 239,
      0,   26,  41,  131, 245, 177, 87,  106, 105, 167, 58,
      158, 184, 244, 65,  205, 42,  40,  80,  134, 52};

  std::vector<unsigned char> aliceTranscript = {
      91,  119, 85,  151, 32,  20,  121, 20,  19,  106, 90,  56,  141, 90,  16,
      210, 14,  244, 60,  251, 140, 48,  190, 65,  194, 35,  166, 246, 1,   209,
      4,   33,  232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235, 97,  118,
      3,   241, 131, 200, 140, 54,  155, 28,  46,  158, 76,  96,  4,   150, 61,
      34,  13,  133, 138, 16,  9,   47,  109, 23,  19,  165, 137, 95,  186, 203,
      186, 154, 179, 116, 3,   160, 119, 225, 180, 226, 19,  172, 45,  113, 125,
      124, 86,  94,  159, 161, 119, 249, 212, 82,  190, 253, 45,  230, 86,  74,
      150, 239, 0,   26,  41,  131, 245, 177, 87,  106, 105, 167, 58,  158, 184,
      244, 65,  205, 42,  40,  80,  134, 52};

  std::vector<unsigned char> aliceHandshake = {
      157, 61,  99,  76,  123, 207, 247, 194, 32,  224, 244, 148, 38,  107,
      158, 13,  66,  237, 6,   32,  9,   98,  120, 172, 63,  45,  144, 194,
      251, 88,  48,  88,  129, 3,   192, 127, 172, 229, 66,  244, 122, 42,
      217, 146, 47,  131, 64,  13,  107, 18,  173, 108, 41,  120, 116, 34,
      129, 5,   243, 248, 99,  109, 135, 104, 46,  19,  83,  20,  244, 153,
      122, 18,  90,  151, 188, 95,  57,  79,  224, 173};

  std::vector<unsigned char> aliceSecretKey = {
      204, 150, 53,  221, 135, 13,  190, 124, 249, 0,   114,
      60,  155, 58,  196, 204, 106, 115, 64,  123, 101, 116,
      92,  214, 170, 19,  239, 225, 138, 163, 113, 129};

  std::vector<unsigned char> bobSecretKey = {
      68,  193, 143, 187, 158, 133, 97, 136, 59,  188, 165,
      11,  242, 164, 152, 180, 9,   15, 203, 5,   115, 123,
      253, 225, 126, 133, 246, 222, 87, 236, 110, 140};

  std::vector<unsigned char> transcript(128);
  std::vector<unsigned char> handshake(80);
  std::vector<unsigned char> ourSecretKey(32);
  std::vector<unsigned char> theirSecretKey(32);

  autograph_init();

  int result = autograph_key_exchange(
      transcript.data(), handshake.data(), ourSecretKey.data(),
      theirSecretKey.data(), 1, alicePrivateIdentityKey.data(),
      alicePublicIdentityKey.data(), alicePrivateEphemeralKey.data(),
      alicePublicEphemeralKey.data(), bobPublicIdentityKey.data(),
      bobPublicEphemeralKey.data());

  REQUIRE(result == 0);
  REQUIRE_THAT(transcript, Catch::Matchers::Equals(aliceTranscript));
  REQUIRE_THAT(handshake, Catch::Matchers::Equals(aliceHandshake));
  REQUIRE_THAT(ourSecretKey, Catch::Matchers::Equals(aliceSecretKey));
  REQUIRE_THAT(theirSecretKey, Catch::Matchers::Equals(bobSecretKey));
}
