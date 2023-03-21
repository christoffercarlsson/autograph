#include "autograph/create_certify.h"

#include "autograph/sign_message.h"

CertifyFunction create_certify(const Chunk &our_private_key,
                               const Chunk &their_public_key) {
  auto certify_function = [&our_private_key,
                           &their_public_key](const Chunk &data) {
    Chunk message;
    if (!data.empty()) {
      message.insert(message.end(), data.begin(), data.end());
    }
    message.insert(message.end(), their_public_key.begin(),
                   their_public_key.end());
    Chunk signature = sign_message(our_private_key, message);
    return std::move(signature);
  };
  return std::move(certify_function);
}
