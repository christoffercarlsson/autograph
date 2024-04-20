#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void authenticate(benchmark::State& benchmarkState) {
  Autograph::KeyPair ourIdentityKeyPair = {
      118, 164, 17,  240, 147, 79,  190, 38,  66,  93,  254, 238, 125,
      202, 197, 2,   56,  252, 122, 177, 18,  187, 249, 208, 29,  149,
      122, 103, 57,  199, 19,  17,  213, 153, 88,  124, 93,  136, 104,
      111, 196, 208, 155, 156, 165, 31,  120, 186, 79,  205, 247, 175,
      243, 184, 114, 80,  152, 243, 24,  225, 91,  220, 141, 150};

  Autograph::PublicKey theirIdentityKey = {
      129, 128, 10,  70,  174, 223, 175, 90,  43, 37,  148,
      125, 188, 163, 110, 136, 15,  246, 192, 76, 167, 8,
      26,  149, 219, 223, 83,  47,  193, 159, 6,  3};

  Autograph::SafetyNumber safetyNumber;

  for (auto _ : benchmarkState) {
    if (!autograph_authenticate(safetyNumber.data(), ourIdentityKeyPair.data(),
                                theirIdentityKey.data())) {
      throw std::runtime_error("Authentication failed");
    }
  }
}

BENCHMARK(authenticate);
