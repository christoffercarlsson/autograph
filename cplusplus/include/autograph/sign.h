#ifndef AUTOGRAPH_SIGN_H
#define AUTOGRAPH_SIGN_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_sign_subject(unsigned char *signature,
                           const unsigned char *private_key,
                           const unsigned char *subject,
                           const unsigned int subject_size);

#ifdef __cplusplus
}  // extern "C"

#include <functional>
#include <vector>

namespace Autograph {

using SignFunction =
    std::function<std::vector<unsigned char>(const std::vector<unsigned char>)>;

SignFunction createSign(const std::vector<unsigned char> identityPrivateKey);

}  // namespace Autograph
#endif

#endif
