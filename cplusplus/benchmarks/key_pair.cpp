#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void session_key_pair(benchmark::State& benchmarkState) {
  Autograph::Bytes keyPair(64);

  for (auto _ : benchmarkState) {
    if (!autograph_session_key_pair(keyPair.data())) {
      throw std::runtime_error("Session key pair generation failed");
    }
  }
}

static void identity_key_pair(benchmark::State& benchmarkState) {
  Autograph::Bytes keyPair(64);

  for (auto _ : benchmarkState) {
    if (!autograph_identity_key_pair(keyPair.data())) {
      throw std::runtime_error("Identity key pair generation failed");
    }
  }
}

BENCHMARK(session_key_pair);
BENCHMARK(identity_key_pair);
