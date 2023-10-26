#include <benchmark/benchmark.h>

#include <stdexcept>
#include <vector>

#include "autograph.h"

std::vector<unsigned char> alicePublicKey = {
    91, 119, 85, 151, 32,  20, 121, 20, 19,  106, 90,  56,  141, 90,  16, 210,
    14, 244, 60, 251, 140, 48, 190, 65, 194, 35,  166, 246, 1,   209, 4,  33};

std::vector<unsigned char> data = {72, 101, 108, 108, 111, 32,
                                   87, 111, 114, 108, 100};

static void sign_data(benchmark::State& state) {
  std::vector<unsigned char> bobPrivateKey = {
      243, 11,  156, 139, 99,  129, 212, 8,   60,  53, 111,
      123, 69,  158, 83,  255, 187, 192, 29,  114, 69, 126,
      243, 111, 122, 143, 170, 247, 140, 129, 60,  0};

  std::vector<unsigned char> signature(64);

  for (auto _ : state) {
    if (autograph_sign_data(signature.data(), bobPrivateKey.data(),
                            alicePublicKey.data(), data.data(),
                            data.size()) != 0) {
      throw std::runtime_error("Sign failed");
    }
  }
}

static void verify_data(benchmark::State& state) {
  std::vector<unsigned char> certificate = {
      123, 223, 90,  28,  163, 65,  187, 199, 14,  78,  92,  116, 38,  48,
      178, 123, 72,  213, 94,  252, 250, 127, 184, 0,   187, 249, 157, 102,
      227, 241, 114, 20,  82,  239, 167, 88,  84,  82,  16,  198, 184, 193,
      35,  9,   78,  135, 162, 198, 47,  53,  179, 3,   242, 165, 38,  18,
      209, 74,  113, 86,  99,  124, 196, 124, 75,  99,  159, 106, 233, 232,
      188, 251, 194, 157, 166, 7,   134, 203, 32,  253, 65,  90,  40,  91,
      76,  25,  252, 156, 139, 154, 148, 183, 71,  7,   109, 5};

  for (auto _ : state) {
    if (autograph_verify_data(alicePublicKey.data(), certificate.data(), 1,
                              data.data(), data.size()) != 0) {
      throw std::runtime_error("Verify failed");
    }
  }
}

BENCHMARK(sign_data);
BENCHMARK(verify_data);
