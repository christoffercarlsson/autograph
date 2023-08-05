#ifndef AUTOGRAPH_INIT_H
#define AUTOGRAPH_INIT_H

#ifdef __cplusplus
extern "C" {
#endif

int autograph_init();

#ifdef __cplusplus
}  // extern "C"

namespace Autograph {

bool init();

}  // namespace Autograph
#endif

#endif
