#include "autograph.h"
#include "external.h"

extern "C" {

bool autograph_ready() { return ready(); }

}  // extern "C"

namespace Autograph {

bool ready() { return autograph_ready(); }

}  // namespace Autograph
