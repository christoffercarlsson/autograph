#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_Auth_00024Companion_autographSafetyNumberSize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_safety_number_size();
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Auth_00024Companion_autographAuthenticate(
    JNIEnv* env, jclass class, jbyteArray safety_number,
    jbyteArray our_identity_key_pair, jbyteArray our_id,
    jbyteArray their_identity_key, jbyteArray their_id) {
  jbyte* safety_number_elements =
      (*env)->GetByteArrayElements(env, safety_number, NULL);
  jbyte* our_identity_key_pair_elements =
      (*env)->GetByteArrayElements(env, our_identity_key_pair, NULL);
  jbyte* our_id_elements = (*env)->GetByteArrayElements(env, our_id, NULL);
  jsize our_id_size = (*env)->GetArrayLength(env, our_id);
  jbyte* their_identity_key_elements =
      (*env)->GetByteArrayElements(env, their_identity_key, NULL);
  jbyte* their_id_elements = (*env)->GetByteArrayElements(env, their_id, NULL);
  jsize their_id_size = (*env)->GetArrayLength(env, their_id);
  bool success = autograph_authenticate(
      (uint8_t*)safety_number_elements,
      (uint8_t*)our_identity_key_pair_elements, (uint8_t*)our_id_elements,
      (size_t)our_id_size, (uint8_t*)their_identity_key_elements,
      (uint8_t*)their_id_elements, (size_t)their_id_size);
  (*env)->ReleaseByteArrayElements(env, safety_number, safety_number_elements,
                                   0);
  (*env)->ReleaseByteArrayElements(env, our_identity_key_pair,
                                   our_identity_key_pair_elements, 0);
    (*env)->ReleaseByteArrayElements(env, our_id,
                                     our_id_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_identity_key,
                                   their_identity_key_elements, 0);
    (*env)->ReleaseByteArrayElements(env, their_id,
                                     their_id_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}
