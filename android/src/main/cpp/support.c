#include <jni.h>

#include "autograph.h"

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Support_00024Companion_autographReady(JNIEnv* env,
                                                        jclass class) {
  bool ready = autograph_ready();
  return ready ? JNI_TRUE : JNI_FALSE;
}
