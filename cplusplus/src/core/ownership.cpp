#include "autograph/core/ownership.h"

#include <vector>

#include "autograph/core/key_pair.h"
#include "autograph/core/message.h"
#include "autograph/crypto/sign.h"

int autograph_core_ownership_certify(unsigned char *signature,
                                     const unsigned char *our_private_key,
                                     const unsigned char *their_public_key,
                                     const unsigned char *data,
                                     const unsigned long long data_size) {
  std::vector<unsigned char> message;
  if (data != nullptr && data_size > 0) {
    message.insert(message.end(), data, data + data_size);
  }
  message.insert(message.end(), their_public_key,
                 their_public_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
  bool success = autograph_crypto_sign(signature, our_private_key,
                                       message.data(), message.size());
  return success ? 0 : -1;
}

int autograph_core_ownership_verify(const unsigned char *their_identity_key,
                                    const unsigned char *their_secret_key,
                                    const unsigned char *certificates,
                                    const unsigned long long certificate_count,
                                    const unsigned char *message,
                                    const unsigned long long message_size) {
  if (certificates == nullptr || certificate_count == 0) {
    return -1;
  }
  std::vector<unsigned char> subject;
  if (message != nullptr && message_size > 0) {
    const unsigned long long data_size =
        message_size - autograph_core_message_EXTRA_SIZE;
    unsigned char data[data_size];
    bool decrypt_result = autograph_core_message_decrypt(data, their_secret_key,
                                                         message, message_size);
    if (!decrypt_result) {
      return -1;
    }
    subject.insert(subject.end(), data, data + data_size);
  }
  subject.insert(subject.end(), their_identity_key,
                 their_identity_key + autograph_core_key_pair_PUBLIC_KEY_SIZE);
  for (unsigned long long i = 0; i < certificate_count; i++) {
    const unsigned char *certificate =
        certificates + i * (autograph_core_key_pair_PUBLIC_KEY_SIZE +
                            autograph_crypto_sign_SIGNATURE_SIZE);
    if (!autograph_crypto_sign_verify(
            certificate, subject.data(), subject.size(),
            certificate + autograph_core_key_pair_PUBLIC_KEY_SIZE)) {
      return -1;
    }
  }
  return 0;
}
