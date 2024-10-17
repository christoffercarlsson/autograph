#include <benchmark/benchmark.h>

#include <stdexcept>

#include "autograph.h"

static void encrypt(benchmark::State& benchmarkState) {
  uint32_t index = 0;

  Autograph::Bytes ciphertext(32);

  Autograph::Bytes key = {
      228, 80,  92,  70,  9,   154, 102, 79,  79, 238, 183,
      1,   104, 239, 123, 93,  228, 74,  44,  60, 147, 21,
      105, 30,  217, 135, 107, 104, 104, 117, 50, 116,
  };

  Autograph::Bytes nonce(12);

  Autograph::Bytes plaintext = {72, 101, 108, 108, 111, 32,
                                87, 111, 114, 108, 100};

  for (auto _ : benchmarkState) {
    nonce = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (!autograph_encrypt(&index, ciphertext.data(), key.data(), nonce.data(),
                           plaintext.data(), plaintext.size())) {
      throw std::runtime_error("Encryption failed");
    }
  }
}

static void decrypt(benchmark::State& benchmarkState) {
  uint32_t index = 0;

  Autograph::Bytes plaintext(16);

  size_t plaintextSize = 0;

  Autograph::Bytes key = {
      228, 80,  92,  70,  9,   154, 102, 79,  79, 238, 183,
      1,   104, 239, 123, 93,  228, 74,  44,  60, 147, 21,
      105, 30,  217, 135, 107, 104, 104, 117, 50, 116,
  };

  Autograph::Bytes nonce(12);

  Autograph::Bytes skippedIndexes(4);

  Autograph::Bytes ciphertext = {253, 199, 105, 203, 139, 136, 132, 228,
                                 198, 157, 65,  140, 116, 90,  212, 112,
                                 55,  190, 186, 221, 205, 80,  46,  24,
                                 161, 117, 201, 113, 133, 213, 29,  105};

  for (auto _ : benchmarkState) {
    nonce = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    skippedIndexes = {0};
    if (!autograph_decrypt(&index, plaintext.data(), &plaintextSize, key.data(),
                           nonce.data(), skippedIndexes.data(),
                           skippedIndexes.size(), ciphertext.data(),
                           ciphertext.size())) {
      throw std::runtime_error("Decryption failed");
    }
  }
}

BENCHMARK(encrypt);
BENCHMARK(decrypt);
