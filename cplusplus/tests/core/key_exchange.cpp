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
      238, 58,  38,  30,  141, 34,  200, 183, 28,  206, 215, 73,  200, 125,
      92,  152, 101, 211, 214, 130, 33,  158, 114, 200, 43,  30,  212, 100,
      176, 149, 15,  111, 170, 186, 36,  10,  90,  136, 46,  170, 120, 191,
      170, 14,  31,  53,  72,  56,  227, 194, 21,  164, 251, 208, 203, 182,
      242, 115, 6,   54,  114, 120, 212, 226, 72,  160, 235, 116, 148, 31,
      19,  62,  52,  116, 28,  172, 227, 191, 95,  152, 15,  140, 105, 200,
      21,  203, 72,  193, 215, 42,  20,  254, 193, 178, 56,  137};

  std::vector<unsigned char> aliceSecretKey = {
      50, 39, 85, 42,  95,  114, 112, 113, 69, 107, 88,
      88, 7,  64, 247, 62,  198, 119, 19,  11, 207, 20,
      76, 33, 81, 185, 177, 24,  255, 204, 65, 152};

  std::vector<unsigned char> bobSecretKey = {
      57,  57,  108, 188, 142, 112, 7,   32,  79,  126, 171,
      206, 154, 13,  92,  105, 189, 213, 214, 43,  82,  217,
      140, 47,  83,  197, 190, 113, 200, 228, 185, 207};

  std::vector<unsigned char> transcript(128);
  std::vector<unsigned char> handshake(96);
  std::vector<unsigned char> ourSecretKey(32);
  std::vector<unsigned char> theirSecretKey(32);

  autograph_init();

  int keyExchangeResult = autograph_key_exchange(
      transcript.data(), handshake.data(), ourSecretKey.data(),
      theirSecretKey.data(), 1, alicePrivateIdentityKey.data(),
      alicePublicIdentityKey.data(), alicePrivateEphemeralKey.data(),
      alicePublicEphemeralKey.data(), bobPublicIdentityKey.data(),
      bobPublicEphemeralKey.data());

  int verificationResult = autograph_key_exchange_verify(
      transcript.data(), alicePublicIdentityKey.data(), ourSecretKey.data(),
      handshake.data());

  REQUIRE(keyExchangeResult == 0);
  REQUIRE(verificationResult == 0);
  REQUIRE_THAT(transcript, Catch::Matchers::Equals(aliceTranscript));
  REQUIRE_THAT(handshake, Catch::Matchers::Equals(aliceHandshake));
  REQUIRE_THAT(ourSecretKey, Catch::Matchers::Equals(aliceSecretKey));
  REQUIRE_THAT(theirSecretKey, Catch::Matchers::Equals(bobSecretKey));
}
