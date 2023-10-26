#include <benchmark/benchmark.h>

#include <vector>

#include "autograph.h"

static void ephemeral_key_pair(benchmark::State& state) {
  std::vector<unsigned char> privateKey(32);
  std::vector<unsigned char> publicKey(32);

  for (auto _ : state) {
    if (autograph_key_pair_ephemeral(privateKey.data(), publicKey.data()) !=
        0) {
      throw std::runtime_error("Ephemeral key pair generation failed");
    }
  }
}

static void identity_key_pair(benchmark::State& state) {
  std::vector<unsigned char> privateKey(32);
  std::vector<unsigned char> publicKey(32);

  for (auto _ : state) {
    if (autograph_key_pair_identity(privateKey.data(), publicKey.data()) != 0) {
      throw std::runtime_error("Identity key pair generation failed");
    }
  }
}

BENCHMARK(ephemeral_key_pair);
BENCHMARK(identity_key_pair);
