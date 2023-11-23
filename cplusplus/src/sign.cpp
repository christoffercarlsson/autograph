#include "sign.h"

#include "error.h"
#include "sizes.h"

namespace Autograph {

SignFunction createSign(const std::vector<unsigned char> identityPrivateKey) {
  SignFunction sign = [identityPrivateKey](std::vector<unsigned char> subject) {
    std::vector<unsigned char> signature(SIGNATURE_SIZE);
    bool success =
        autograph_sign_subject(signature.data(), identityPrivateKey.data(),
                               subject.data(), subject.size()) == 0;
    if (!success) {
      throw Error(Error::Signing);
    }
    return signature;
  };
  return sign;
}

}  // namespace Autograph
