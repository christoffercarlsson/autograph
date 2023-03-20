#include "autograph/create_verify.h"

VerifyFunction create_verify(const Chunk &our_private_key,
                             const Chunk &their_public_key) {
  auto verify_functon = [&our_private_key, &their_public_key](
                            const std::vector<Certificate> &certificates,
                            const Chunk &message) {
    if (certificates.empty()) {
      return false;
    }
    Chunk subject;
    if (!data.empty()) {
      subject.insert(subject.end(), data.begin(), data.end());
    }
    subject.insert(subject.end(), their_public_key.begin(),
                   their_public_key.end());
    for (const auto &certificate : certificates) {
      if (!verify_signature(certificate.identity_key, subject,
                            certificate.signature)) {
        return false;
      }
    }
    return true;
  };
  return std::move(verify_function);
}
