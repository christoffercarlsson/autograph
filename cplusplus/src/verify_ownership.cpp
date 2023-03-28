#include "autograph/verify_ownership.h"

#include <vector>

#include "autograph/constants.h"
#include "autograph/decrypt_message.h"
#include "autograph/verify_signature.h"

bool verify_ownership(const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *certificates,
                      const unsigned long long certificate_count,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  if (certificates == nullptr || certificate_count == 0) {
    return false;
  }
  auto subject = std::vector<unsigned char>();
  if (message != nullptr && message_size > 0) {
    const unsigned long long data_size = message_size - MESSAGE_EXTRA_SIZE;
    unsigned char data[data_size];
    bool decrypt_result =
        decrypt_message(data, their_secret_key, message, message_size);
    if (!decrypt_result) {
      return false;
    }
    subject.insert(subject.end(), data, data + data_size);
  }
  subject.insert(subject.end(), their_identity_key,
                 their_identity_key + PUBLIC_KEY_SIZE);
  for (unsigned long long i = 0; i < certificate_count; i++) {
    const unsigned char *certificate =
        certificates + i * (PUBLIC_KEY_SIZE + SIGNATURE_SIZE);
    if (!verify_signature(certificate, subject.data(), subject.size(),
                          certificate + PUBLIC_KEY_SIZE)) {
      return false;
    }
  }
  return true;
}
