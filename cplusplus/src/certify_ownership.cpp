#include "autograph/certify_ownership.h"

#include <vector>

#include "autograph/constants.h"
#include "autograph/sign_message.h"

bool certify_ownership(unsigned char *signature,
                       const unsigned char *our_private_key,
                       const unsigned char *their_public_key,
                       const unsigned char *data,
                       const unsigned long long data_size) {
  std::vector<unsigned char> message;
  if (data != nullptr && data_size > 0) {
    message.insert(message.end(), data, data + data_size);
  }
  message.insert(message.end(), their_public_key,
                 their_public_key + PUBLIC_KEY_SIZE);
  return sign_message(signature, our_private_key, message.data(),
                      message.size());
}
