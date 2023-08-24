#include "sign.h"

#include "private.h"

namespace Autograph {

SignResult createErrorResult() {
  Bytes signature(64, 0);
  return {false, signature};
}

SignFunction createSafeSign(const SignFunction sign) {
  SignFunction safeSign = [sign](const Bytes subject) {
    try {
      auto signResult = sign(subject);
      if (signResult.signature.size() != 64) {
        return createErrorResult();
      }
      return signResult;
    } catch (...) {
      return createErrorResult();
    }
  };
  return safeSign;
}

SignFunction createSign(const Bytes identityPrivateKey) {
  SignFunction sign = [identityPrivateKey](Bytes subject) {
    Bytes signature(64);
    bool success =
        autograph_sign_subject(signature.data(), identityPrivateKey.data(),
                               subject.data(), subject.size()) == 0;
    SignResult result = {success, signature};
    return result;
  };
  return sign;
}

}  // namespace Autograph
