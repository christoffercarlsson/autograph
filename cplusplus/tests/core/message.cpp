#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_vector.hpp>
#include <vector>

#include "autograph.h"

TEST_CASE("Message", "[core_message]") {
  std::vector<unsigned char> secretKey = {
      204, 150, 53,  221, 135, 13,  190, 124, 249, 0,   114,
      60,  155, 58,  196, 204, 106, 115, 64,  123, 101, 116,
      92,  214, 170, 19,  239, 225, 138, 163, 113, 129};

  std::vector<unsigned char> plaintext = {72, 101, 108, 108, 111, 32,
                                          87, 111, 114, 108, 100};

  std::vector<unsigned char> message = {
      0,   0,   0,  0,   0,   0,   0,   1,   203, 203, 240, 117,
      151, 142, 77, 113, 252, 151, 171, 12,  154, 177, 105, 6,
      248, 79,  37, 105, 238, 243, 135, 194, 50,  34,  253};

  std::vector<unsigned char> encrypted(plaintext.size() + 24);
  std::vector<unsigned char> decrypted(plaintext.size());

  autograph_init();

  int encryptResult = autograph_encrypt(encrypted.data(), secretKey.data(), 1,
                                        plaintext.data(), plaintext.size());
  int decryptResult = autograph_decrypt(decrypted.data(), secretKey.data(),
                                        encrypted.data(), encrypted.size());

  REQUIRE(encryptResult == 0);
  REQUIRE(decryptResult == 0);
  REQUIRE_THAT(encrypted, Catch::Matchers::Equals(message));
  REQUIRE_THAT(decrypted, Catch::Matchers::Equals(plaintext));
}
