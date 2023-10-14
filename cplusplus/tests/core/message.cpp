#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Message", "[core_message]") {
  std::vector<unsigned char> ourSecretKey = {
      50, 39, 85, 42,  95,  114, 112, 113, 69, 107, 88,
      88, 7,  64, 247, 62,  198, 119, 19,  11, 207, 20,
      76, 33, 81, 185, 177, 24,  255, 204, 65, 152};

  std::vector<unsigned char> theirSecretKey = {
      50, 39, 85, 42,  95,  114, 112, 113, 69, 107, 88,
      88, 7,  64, 247, 62,  198, 119, 19,  11, 207, 20,
      76, 33, 81, 185, 177, 24,  255, 204, 65, 152};

  std::vector<unsigned char> plaintext = {72, 101, 108, 108, 111, 32,
                                          87, 111, 114, 108, 100};

  std::vector<unsigned char> message = {133, 247, 214, 87,  210, 66,  77,  105,
                                        105, 94,  229, 248, 76,  207, 31,  228,
                                        73,  37,  32,  45,  125, 163, 240, 75,
                                        45,  197, 224, 166, 218, 59,  107, 249};

  auto ciphertextSize = autograph_ciphertext_size(plaintext.size());
  auto plaintextSize = autograph_plaintext_size(ciphertextSize);

  std::vector<unsigned char> encrypted(ciphertextSize);
  std::vector<unsigned char> decrypted(plaintextSize);
  std::vector<unsigned char> messageIndex(8);
  std::vector<unsigned char> decryptIndex(8);
  std::vector<unsigned char> skippedKeys(40002);
  std::vector<unsigned char> encryptIndex(8);

  autograph_init();

  int encryptResult = autograph_encrypt(encrypted.data(), encryptIndex.data(),
                                        ourSecretKey.data(), plaintext.data(),
                                        plaintext.size());

  int decryptResult = autograph_decrypt(
      decrypted.data(), NULL, messageIndex.data(), decryptIndex.data(),
      skippedKeys.data(), theirSecretKey.data(), encrypted.data(),
      encrypted.size());

  decrypted.resize(plaintext.size());

  REQUIRE(encryptResult == 0);
  REQUIRE(decryptResult == 0);
  REQUIRE_THAT(encrypted, Catch::Matchers::Equals(message));
  REQUIRE_THAT(decrypted, Catch::Matchers::Equals(plaintext));
}
