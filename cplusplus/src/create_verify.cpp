#include "autograph/create_verify.h"

#include "autograph/verify_signature.h"

VerifyFunction create_verify(const Chunk &their_identity_key,
                             const DecryptFunction &decrypt) {
  auto verify_function = [&their_identity_key, &decrypt](
                             const CertificateList &certificates,
                             const Chunk &message) {
    if (certificates.empty()) {
      return false;
    }
    try {
      Chunk subject;
      if (!message.empty()) {
        auto data = decrypt(message);
        subject.insert(subject.end(), data.begin(), data.end());
      }
      subject.insert(subject.end(), their_identity_key.begin(),
                     their_identity_key.end());
      for (const auto &certificate : certificates) {
        if (!verify_signature(certificate.identity_key, subject,
                              certificate.signature)) {
          return false;
        }
      }
    } catch (const std::exception &error) {
      return false;
    }
    return true;
  };
  return std::move(verify_function);
}
