#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void certify(benchmark::State& benchmarkState) {
  Autograph::Bytes ourIdentityKeyPair = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93,  254, 238, 125,
      202, 197, 2,   56,  252, 122, 177, 18,  187, 249, 208, 29,  149,
      122, 103, 57,  199, 19,  17,  213, 153, 88,  124, 93,  136, 104,
      111, 196, 208, 155, 156, 165, 31,  120, 186, 79,  205, 247, 175,
      243, 184, 114, 80,  152, 243, 24,  225, 91,  220, 141, 150};

  Autograph::Bytes theirIdentityKey = {129, 128, 10,  70,  174, 223, 175, 90,
                                       43,  37,  148, 125, 188, 163, 110, 136,
                                       15,  246, 192, 76,  167, 8,   26,  149,
                                       219, 223, 83,  47,  193, 159, 6,   3};

  Autograph::Bytes data = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

  Autograph::Bytes signature(64);

  for (auto _ : benchmarkState) {
    if (!autograph_certify(signature.data(), ourIdentityKeyPair.data(),
                           theirIdentityKey.data(), data.data(), data.size())) {
      throw std::runtime_error("Certification failed");
    }
  }
}

static void verify(benchmark::State& benchmarkState) {
  Autograph::Bytes ownerIdentityKey = {213, 153, 88,  124, 93,  136, 104, 111,
                                       196, 208, 155, 156, 165, 31,  120, 186,
                                       79,  205, 247, 175, 243, 184, 114, 80,
                                       152, 243, 24,  225, 91,  220, 141, 150};

  Autograph::Bytes certifierIdentityKey = {
      129, 128, 10,  70,  174, 223, 175, 90,  43, 37,  148,
      125, 188, 163, 110, 136, 15,  246, 192, 76, 167, 8,
      26,  149, 219, 223, 83,  47,  193, 159, 6,  3};

  Autograph::Bytes signature = {
      231, 126, 138, 39,  145, 83,  130, 243, 2,   56,  53,  185, 199,
      242, 217, 239, 118, 208, 172, 6,   201, 132, 94,  179, 57,  59,
      160, 23,  150, 221, 67,  122, 176, 56,  160, 63,  7,   161, 169,
      101, 240, 97,  108, 137, 142, 99,  197, 44,  179, 142, 37,  4,
      135, 162, 118, 160, 119, 245, 234, 39,  26,  75,  71,  6};

  Autograph::Bytes data = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

  for (auto _ : benchmarkState) {
    if (!autograph_verify(ownerIdentityKey.data(), certifierIdentityKey.data(),
                          signature.data(), data.data(), data.size())) {
      throw std::runtime_error("Verification failed");
    }
  }
}

BENCHMARK(certify);
BENCHMARK(verify);
