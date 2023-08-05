#include "sign.h"

#include "private.h"

namespace Autograph {

SignResult create_error_result() {
  Bytes signature(64, 0);
  SignResult result = {false, signature};
  return result;
}

SignFunction create_safe_sign(const SignFunction sign) {
  SignFunction safe_sign = [sign](const Bytes subject) {
    try {
      auto sign_result = sign(subject);
      if (sign_result.signature.size() != 64) {
        return create_error_result();
      }
      return sign_result;
    } catch (...) {
      return create_error_result();
    }
  };
  return safe_sign;
}

SignFunction create_sign(const Bytes identity_private_key) {
  SignFunction sign = [identity_private_key](Bytes subject) {
    Bytes signature(64);
    bool success = autograph_sign(signature.data(), identity_private_key.data(),
                                  subject.data(), subject.size()) == 0;
    SignResult result = {success, signature};
    return result;
  };
  return sign;
}

}  // namespace Autograph
