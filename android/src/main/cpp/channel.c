#include <jni.h>

#include "autograph.h"

JNIEXPORT void JNICALL
Java_sh_autograph_Channel_00024Companion_autographUseKeyPairs(
    JNIEnv* env, jclass class, jbyteArray identity_key_pair,
    jbyteArray session_key_pair, jbyteArray our_identity_key_pair,
    jbyteArray our_session_key_pair) {
  jbyte* identity_key_pair_elements =
      (*env)->GetByteArrayElements(env, identity_key_pair, NULL);
  jbyte* session_key_pair_elements =
      (*env)->GetByteArrayElements(env, session_key_pair, NULL);
  jbyte* our_identity_key_pair_elements =
      (*env)->GetByteArrayElements(env, our_identity_key_pair, NULL);
  jbyte* our_session_key_pair_elements =
      (*env)->GetByteArrayElements(env, our_session_key_pair, NULL);
  autograph_use_key_pairs((uint8_t*)identity_key_pair_elements,
                          (uint8_t*)session_key_pair_elements,
                          (uint8_t*)our_identity_key_pair_elements,
                          (uint8_t*)our_session_key_pair_elements);

  (*env)->ReleaseByteArrayElements(env, identity_key_pair,
                                   identity_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, session_key_pair,
                                   session_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, our_identity_key_pair,
                                   our_identity_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, our_session_key_pair,
                                   our_session_key_pair_elements, 0);
}

JNIEXPORT void JNICALL
Java_sh_autograph_Channel_00024Companion_autographUsePublicKeys(
    JNIEnv* env, jclass class, jbyteArray identity_key, jbyteArray session_key,
    jbyteArray their_identity_key, jbyteArray their_session_key) {
  jbyte* identity_key_elements =
      (*env)->GetByteArrayElements(env, identity_key, NULL);
  jbyte* session_key_elements =
      (*env)->GetByteArrayElements(env, session_key, NULL);
  jbyte* their_identity_key_elements =
      (*env)->GetByteArrayElements(env, their_identity_key, NULL);
  jbyte* their_session_key_elements =
      (*env)->GetByteArrayElements(env, their_session_key, NULL);
  autograph_use_public_keys((uint8_t*)identity_key_elements,
                            (uint8_t*)session_key_elements,
                            (uint8_t*)their_identity_key_elements,
                            (uint8_t*)their_session_key_elements);
  (*env)->ReleaseByteArrayElements(env, identity_key, identity_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, session_key, session_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_identity_key,
                                   their_identity_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_session_key,
                                   their_session_key_elements, 0);
}
