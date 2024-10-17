#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void key_exchange(benchmark::State &benchmarkState) {
  Autograph::Bytes ourIdentityKeyPair = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93,  254, 238, 125,
      202, 197, 2,   56,  252, 122, 177, 18,  187, 249, 208, 29,  149,
      122, 103, 57,  199, 19,  17,  213, 153, 88,  124, 93,  136, 104,
      111, 196, 208, 155, 156, 165, 31,  120, 186, 79,  205, 247, 175,
      243, 184, 114, 80,  152, 243, 24,  225, 91,  220, 141, 150};

  Autograph::Bytes ourSessionKeyPair = {
      201, 142, 54,  248, 151, 150, 224, 79,  30,  126, 207, 157, 118,
      85,  9,   212, 148, 156, 73,  176, 107, 107, 47,  111, 95,  98,
      33,  192, 80,  223, 48,  221, 35,  16,  23,  37,  205, 131, 166,
      97,  13,  81,  136, 246, 193, 253, 139, 193, 230, 155, 222, 221,
      37,  114, 190, 87,  104, 44,  210, 144, 127, 176, 198, 45};

  Autograph::Bytes theirIdentityKey = {177, 67,  45,  125, 158, 190, 181, 222,
                                       101, 149, 224, 200, 223, 235, 222, 110,
                                       67,  61,  200, 62,  29,  37,  150, 228,
                                       137, 114, 143, 77,  115, 135, 143, 103};

  Autograph::Bytes theirSessionKey = {88, 115, 171, 4,   34,  181, 120, 21,
                                      10, 39,  204, 215, 158, 210, 177, 243,
                                      28, 138, 52,  91,  236, 55,  30,  117,
                                      10, 125, 87,  232, 80,  6,   232, 93};

  Autograph::Bytes transcript(64);

  Autograph::Bytes signature(64);

  Autograph::Bytes sendingKey(32);

  Autograph::Bytes receivingKey(32);

  for (auto _ : benchmarkState) {
    if (!autograph_key_exchange(
            transcript.data(), signature.data(), sendingKey.data(),
            receivingKey.data(), true, ourIdentityKeyPair.data(),
            ourSessionKeyPair.data(), theirIdentityKey.data(),
            theirSessionKey.data())) {
      throw std::runtime_error("Key exchange failed");
    }
  }
}

static void verify_key_exchange(benchmark::State &benchmarkState) {
  Autograph::Bytes transcript = {
      213, 153, 88,  124, 93,  136, 104, 111, 196, 208, 155, 156, 165, 31,  120,
      186, 79,  205, 247, 175, 243, 184, 114, 80,  152, 243, 24,  225, 91,  220,
      141, 150, 35,  16,  23,  37,  205, 131, 166, 97,  13,  81,  136, 246, 193,
      253, 139, 193, 230, 155, 222, 221, 37,  114, 190, 87,  104, 44,  210, 144,
      127, 176, 198, 45,  177, 67,  45,  125, 158, 190, 181, 222, 101, 149, 224,
      200, 223, 235, 222, 110, 67,  61,  200, 62,  29,  37,  150, 228, 137, 114,
      143, 77,  115, 135, 143, 103, 88,  115, 171, 4,   34,  181, 120, 21,  10,
      39,  204, 215, 158, 210, 177, 243, 28,  138, 52,  91,  236, 55,  30,  117,
      10,  125, 87,  232, 80,  6,   232, 93};

  Autograph::Bytes ourIdentityKeyPair = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93,  254, 238, 125,
      202, 197, 2,   56,  252, 122, 177, 18,  187, 249, 208, 29,  149,
      122, 103, 57,  199, 19,  17,  213, 153, 88,  124, 93,  136, 104,
      111, 196, 208, 155, 156, 165, 31,  120, 186, 79,  205, 247, 175,
      243, 184, 114, 80,  152, 243, 24,  225, 91,  220, 141, 150};

  Autograph::Bytes theirIdentityKey = {177, 67,  45,  125, 158, 190, 181, 222,
                                       101, 149, 224, 200, 223, 235, 222, 110,
                                       67,  61,  200, 62,  29,  37,  150, 228,
                                       137, 114, 143, 77,  115, 135, 143, 103};

  Autograph::Bytes theirSignature = {
      22,  51,  47,  208, 198, 143, 141, 242, 199, 185, 82,  142, 190,
      105, 55,  152, 145, 185, 67,  35,  122, 253, 201, 23,  74,  40,
      110, 217, 60,  198, 123, 216, 195, 74,  74,  185, 65,  215, 2,
      151, 214, 117, 91,  122, 16,  145, 253, 88,  26,  50,  135, 226,
      45,  126, 125, 22,  88,  214, 178, 147, 69,  72,  143, 3};

  for (auto _ : benchmarkState) {
    if (!autograph_verify_key_exchange(
            transcript.data(), ourIdentityKeyPair.data(),
            theirIdentityKey.data(), theirSignature.data())) {
      throw std::runtime_error("Key exchange verification failed");
    }
  }
}

BENCHMARK(key_exchange);
BENCHMARK(verify_key_exchange);
