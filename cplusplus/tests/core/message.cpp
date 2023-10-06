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

  std::vector<unsigned char> message = {
      133, 247, 214, 87, 210, 66, 77,  105, 105, 94,  229, 171, 72, 191,
      74,  90,  69,  11, 177, 60, 219, 207, 74,  250, 37,  63,  165};

  std::vector<unsigned char> encrypted(plaintext.size() + 16);
  std::vector<unsigned char> decrypted(plaintext.size());
  std::vector<unsigned char> messageIndex(8);
  std::vector<unsigned char> decryptIndex(8);
  std::vector<unsigned char> skippedKeys(40002);
  std::vector<unsigned char> encryptIndex(8);

  autograph_init();

  int encryptResult = autograph_encrypt(encrypted.data(), encryptIndex.data(),
                                        ourSecretKey.data(), plaintext.data(),
                                        plaintext.size());

  int decryptResult = autograph_decrypt(decrypted.data(), messageIndex.data(),
                                        decryptIndex.data(), skippedKeys.data(),
                                        theirSecretKey.data(), encrypted.data(),
                                        encrypted.size());

  REQUIRE(encryptResult == 0);
  REQUIRE(decryptResult == 0);
  REQUIRE_THAT(encrypted, Catch::Matchers::Equals(message));
  REQUIRE_THAT(decrypted, Catch::Matchers::Equals(plaintext));
}
