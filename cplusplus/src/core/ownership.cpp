#include <vector>

#include "autograph.h"
#include "constants.hpp"
#include "crypto.hpp"

namespace autograph {

bool calculate_subject(std::vector<unsigned char> &subject,
                       const unsigned char *their_public_key,
                       const unsigned char *their_secret_key,
                       const unsigned char *message,
                       const unsigned long long message_size) {
  if (message != nullptr && message_size > 0) {
    std::vector<unsigned char> data(message_size - MESSAGE_EXTRA_SIZE);
    bool decrypt_result = autograph_decrypt(data.data(), their_secret_key,
                                            message, message_size) == 0;
    if (!decrypt_result) {
      return false;
    }
    subject.insert(subject.end(), data.begin(), data.end());
  }
  subject.insert(subject.end(), their_public_key,
                 their_public_key + PUBLIC_KEY_SIZE);
  return true;
}

}  // namespace autograph

int autograph_certify(unsigned char *signature,
                      const unsigned char *our_private_key,
                      const unsigned char *their_public_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *message,
                      const unsigned long long message_size) {
  std::vector<unsigned char> subject;
  bool subject_result = autograph::calculate_subject(
      subject, their_public_key, their_secret_key, message, message_size);
  if (!subject_result) {
    return -1;
  }
  return autograph::sign(signature, our_private_key, subject.data(),
                         subject.size())
             ? 0
             : -1;
}

int autograph_verify(const unsigned char *their_public_key,
                     const unsigned char *their_secret_key,
                     const unsigned char *certificates,
                     const unsigned long long certificate_count,
                     const unsigned char *message,
                     const unsigned long long message_size) {
  if (certificates == nullptr || certificate_count == 0) {
    return -1;
  }
  std::vector<unsigned char> subject;
  bool subject_result = autograph::calculate_subject(
      subject, their_public_key, their_secret_key, message, message_size);
  if (!subject_result) {
    return -1;
  }
  for (unsigned long long i = 0; i < certificate_count; i++) {
    const unsigned char *certificate =
        certificates +
        i * (autograph::PUBLIC_KEY_SIZE + autograph::SIGNATURE_SIZE);
    bool verify_result =
        autograph::verify(certificate, subject.data(), subject.size(),
                          certificate + autograph::PUBLIC_KEY_SIZE);
    if (!verify_result) {
      return -1;
    }
  }
  return 0;
}
