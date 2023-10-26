#include <benchmark/benchmark.h>

#include <stdexcept>
#include <vector>

#include "autograph.h"

std::vector<unsigned char> alicePrivateIdentityKey = {
    43, 6,  246, 172, 137, 170, 33,  12, 118, 177, 111, 60, 19, 37, 65, 122,
    28, 34, 200, 251, 96,  35,  187, 52, 74,  224, 143, 39, 90, 51, 33, 140};

std::vector<unsigned char> alicePublicIdentityKey = {
    91, 119, 85, 151, 32,  20, 121, 20, 19,  106, 90,  56,  141, 90,  16, 210,
    14, 244, 60, 251, 140, 48, 190, 65, 194, 35,  166, 246, 1,   209, 4,  33};

std::vector<unsigned char> alicePublicEphemeralKey = {
    16,  9,   47,  109, 23,  19,  165, 137, 95,  186, 203,
    186, 154, 179, 116, 3,   160, 119, 225, 180, 226, 19,
    172, 45,  113, 125, 124, 86,  94,  159, 161, 119};

std::vector<unsigned char> bobPublicIdentityKey = {
    232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235,
    97,  118, 3,   241, 131, 200, 140, 54,  155, 28,  46,
    158, 76,  96,  4,   150, 61,  34,  13,  133, 138};

std::vector<unsigned char> bobPublicEphemeralKey = {
    249, 212, 82,  190, 253, 45, 230, 86,  74,  150, 239, 0,  26, 41, 131, 245,
    177, 87,  106, 105, 167, 58, 158, 184, 244, 65,  205, 42, 40, 80, 134, 52};

static void key_exchange(benchmark::State& state) {
  std::vector<unsigned char> transcript(128);
  std::vector<unsigned char> handshake(96);
  std::vector<unsigned char> ourSecretKey(32);
  std::vector<unsigned char> theirSecretKey(32);

  for (auto _ : state) {
    std::vector<unsigned char> alicePrivateEphemeralKey = {
        171, 243, 152, 144, 76,  145, 84,  13,  243, 173, 102,
        244, 84,  223, 43,  104, 182, 128, 230, 247, 121, 221,
        222, 203, 10,  80,  43,  88,  177, 155, 1,   114};

    if (autograph_key_exchange(
            transcript.data(), handshake.data(), ourSecretKey.data(),
            theirSecretKey.data(), 1, alicePrivateIdentityKey.data(),
            alicePublicIdentityKey.data(), alicePrivateEphemeralKey.data(),
            alicePublicEphemeralKey.data(), bobPublicIdentityKey.data(),
            bobPublicEphemeralKey.data()) != 0) {
      throw std::runtime_error("Key exchange failed");
    }
  }
}

static void key_exchange_verify(benchmark::State& state) {
  std::vector<unsigned char> transcript = {
      91,  119, 85,  151, 32,  20,  121, 20,  19,  106, 90,  56,  141, 90,  16,
      210, 14,  244, 60,  251, 140, 48,  190, 65,  194, 35,  166, 246, 1,   209,
      4,   33,  232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235, 97,  118,
      3,   241, 131, 200, 140, 54,  155, 28,  46,  158, 76,  96,  4,   150, 61,
      34,  13,  133, 138, 16,  9,   47,  109, 23,  19,  165, 137, 95,  186, 203,
      186, 154, 179, 116, 3,   160, 119, 225, 180, 226, 19,  172, 45,  113, 125,
      124, 86,  94,  159, 161, 119, 249, 212, 82,  190, 253, 45,  230, 86,  74,
      150, 239, 0,   26,  41,  131, 245, 177, 87,  106, 105, 167, 58,  158, 184,
      244, 65,  205, 42,  40,  80,  134, 52};

  std::vector<unsigned char> handshake = {
      40,  96,  87,  46,  204, 210, 12,  62,  80,  86,  55,  252, 191, 201,
      183, 188, 150, 80,  124, 92,  248, 44,  173, 8,   66,  54,  229, 117,
      245, 117, 243, 248, 77,  227, 184, 224, 105, 115, 69,  212, 103, 64,
      198, 124, 122, 196, 195, 215, 250, 95,  169, 218, 185, 119, 150, 206,
      130, 255, 243, 124, 48,  52,  32,  211, 77,  244, 171, 54,  222, 115,
      138, 209, 166, 140, 240, 181, 115, 173, 224, 224, 108, 145, 15,  210,
      138, 188, 76,  13,  29,  19,  188, 120, 188, 109, 89,  34};

  std::vector<unsigned char> secretKey = {
      57,  57,  108, 188, 142, 112, 7,   32,  79,  126, 171,
      206, 154, 13,  92,  105, 189, 213, 214, 43,  82,  217,
      140, 47,  83,  197, 190, 113, 200, 228, 185, 207};

  for (auto _ : state) {
    if (autograph_key_exchange_verify(
            transcript.data(), alicePublicIdentityKey.data(), secretKey.data(),
            handshake.data()) != 0) {
      // throw std::runtime_error("Key exchange verification failed");
    }
  }
}

BENCHMARK(key_exchange);
BENCHMARK(key_exchange_verify);
