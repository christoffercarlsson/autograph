#include <benchmark/benchmark.h>

#include <stdexcept>
#include <vector>

#include "autograph.h"

static void encrypt(benchmark::State& state) {
  std::vector<unsigned char> secretKey = {
      50, 39, 85, 42,  95,  114, 112, 113, 69, 107, 88,
      88, 7,  64, 247, 62,  198, 119, 19,  11, 207, 20,
      76, 33, 81, 185, 177, 24,  255, 204, 65, 152};

  std::vector<unsigned char> plaintext = {72, 101, 108, 108, 111, 32,
                                          87, 111, 114, 108, 100};

  std::vector<unsigned char> message(32);
  std::vector<unsigned char> index(8);

  for (auto _ : state) {
    if (autograph_encrypt(message.data(), index.data(), secretKey.data(),
                          plaintext.data(), plaintext.size()) != 0) {
      throw std::runtime_error("Encryption failed");
    }
  }
}

static void decrypt(benchmark::State& state) {
  std::vector<unsigned char> message = {133, 247, 214, 87,  210, 66,  77,  105,
                                        105, 94,  229, 248, 76,  207, 31,  228,
                                        73,  37,  32,  45,  125, 163, 240, 75,
                                        45,  197, 224, 166, 218, 59,  107, 249};

  for (auto _ : state) {
    std::vector<unsigned char> secretKey = {
        50, 39, 85, 42,  95,  114, 112, 113, 69, 107, 88,
        88, 7,  64, 247, 62,  198, 119, 19,  11, 207, 20,
        76, 33, 81, 185, 177, 24,  255, 204, 65, 152};

    std::vector<unsigned char> messageIndex(8);
    std::vector<unsigned char> decryptIndex(8);
    std::vector<unsigned char> skippedKeys(40002);
    std::vector<unsigned char> plaintext(16);

    if (autograph_decrypt(plaintext.data(), NULL, messageIndex.data(),
                          decryptIndex.data(), skippedKeys.data(),
                          secretKey.data(), message.data(),
                          message.size()) != 0) {
      throw std::runtime_error("Decryption failed");
    }
  }
}

BENCHMARK(encrypt);
BENCHMARK(decrypt);
