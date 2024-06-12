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
      35,  16,  23,  37,  205, 131, 166, 97,  13,  81,  136, 246, 193,
      253, 139, 193, 230, 155, 222, 221, 37,  114, 190, 87,  104, 44,
      210, 144, 127, 176, 198, 45,  88,  115, 171, 4,   34,  181, 120,
      21,  10,  39,  204, 215, 158, 210, 177, 243, 28,  138, 52,  91,
      236, 55,  30,  117, 10,  125, 87,  232, 80,  6,   232, 93};

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
      89,  193, 59,  76,  215, 36,  171, 145, 63, 32,  134, 60,  225,
      112, 136, 191, 176, 64,  42,  18,  210, 2,  33,  212, 243, 245,
      230, 147, 182, 20,  81,  101, 170, 221, 69, 164, 224, 166, 188,
      170, 197, 114, 55,  218, 48,  218, 29,  56, 98,  91,  236, 12,
      10,  64,  82,  140, 15,  76,  243, 188, 24, 236, 62,  5};

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
