#include <benchmark/benchmark.h>

#include <stdexcept>
#include <vector>

#include "autograph.h"

std::vector<unsigned char> aliceIdentityKey = {
    91, 119, 85, 151, 32,  20, 121, 20, 19,  106, 90,  56,  141, 90,  16, 210,
    14, 244, 60, 251, 140, 48, 190, 65, 194, 35,  166, 246, 1,   209, 4,  33};

std::vector<unsigned char> bobIdentityKey = {
    232, 130, 200, 162, 218, 101, 75,  210, 196, 152, 235,
    97,  118, 3,   241, 131, 200, 140, 54,  155, 28,  46,
    158, 76,  96,  4,   150, 61,  34,  13,  133, 138};

static void safety_number(benchmark::State& state) {
  std::vector<unsigned char> safetyNumber(60);
  for (auto _ : state) {
    if (autograph_safety_number(safetyNumber.data(), aliceIdentityKey.data(),
                                bobIdentityKey.data()) != 0) {
      throw std::runtime_error("Safety number failed");
    }
  }
}

BENCHMARK(safety_number);
