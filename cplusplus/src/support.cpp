#include "autograph.h"
#include "primitives.h"

extern "C" {

bool autograph_ready() { return autograph_primitive_ready(); }

}  // extern "C"

namespace Autograph {

bool ready() { return autograph_ready(); }

}  // namespace Autograph
