#include <jni.h>

#include "autograph.h"

JNIEXPORT jboolean JNICALL
Java_sh_autograph_KeyPair_00024Companion_autographIdentityKeyPair(
    JNIEnv* env, jclass class, jbyteArray key_pair) {
  jbyte* elements = (*env)->GetByteArrayElements(env, key_pair, NULL);
  bool success = autograph_identity_key_pair((uint8_t*)elements);
  (*env)->ReleaseByteArrayElements(env, key_pair, elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_KeyPair_00024Companion_autographSessionKeyPair(
    JNIEnv* env, jclass class, jbyteArray key_pair) {
  jbyte* elements = (*env)->GetByteArrayElements(env, key_pair, NULL);
  bool success = autograph_session_key_pair((uint8_t*)elements);
  (*env)->ReleaseByteArrayElements(env, key_pair, elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_sh_autograph_KeyPair_00024Companion_autographGetPublicKey(
    JNIEnv* env, jclass class, jbyteArray public_key, jbyteArray key_pair) {
  jbyte* public_key_elements =
      (*env)->GetByteArrayElements(env, public_key, NULL);
  jbyte* key_pair_elements = (*env)->GetByteArrayElements(env, key_pair, NULL);
  autograph_get_public_key((uint8_t*)public_key_elements,
                           (uint8_t*)key_pair_elements);
  (*env)->ReleaseByteArrayElements(env, public_key, public_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, key_pair, key_pair_elements, 0);
}
