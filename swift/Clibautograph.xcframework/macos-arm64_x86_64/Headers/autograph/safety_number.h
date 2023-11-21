#ifndef AUTOGRAPH_SAFETY_NUMBER_H
#define AUTOGRAPH_SAFETY_NUMBER_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_safety_number(unsigned char *safety_number,
                            const unsigned char *our_identity_key,
                            const unsigned char *their_identity_key);

#ifdef __cplusplus
}  // extern "C"

#include <vector>

namespace Autograph {

std::vector<unsigned char> calculateSafetyNumber(std::vector<unsigned char> a,
                                                 std::vector<unsigned char> b);

}  // namespace Autograph

#endif

#endif
