#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_Helper_00024Companion_autographKeyPairSize(JNIEnv* env,
                                                             jclass class) {
  return (jint)autograph_key_pair_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Helper_00024Companion_autographNonceSize(JNIEnv* env,
                                                           jclass class) {
  return (jint)autograph_nonce_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Helper_00024Companion_autographPublicKeySize(JNIEnv* env,
                                                               jclass class) {
  return (jint)autograph_public_key_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Helper_00024Companion_autographSecretKeySize(JNIEnv* env,
                                                               jclass class) {
  return (jint)autograph_secret_key_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Helper_00024Companion_autographSignatureSize(JNIEnv* env,
                                                               jclass class) {
  return (jint)autograph_signature_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Helper_00024Companion_autographTranscriptSize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_transcript_size();
}

JNIEXPORT void JNICALL Java_sh_autograph_Helper_00024Companion_autographZeroize(
    JNIEnv* env, jclass class, jbyteArray data) {
  jbyte* data_elements = (*env)->GetByteArrayElements(env, data, NULL);
  jsize data_size = (*env)->GetArrayLength(env, data);
  autograph_zeroize((uint8_t*)data_elements, (size_t)data_size);
  (*env)->ReleaseByteArrayElements(env, data, data_elements, 0);
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Helper_00024Companion_autographIsZero(JNIEnv* env,
                                                        jclass class,
                                                        jbyteArray data) {
  jbyte* data_elements = (*env)->GetByteArrayElements(env, data, NULL);
  jsize data_size = (*env)->GetArrayLength(env, data);
  bool is_zero = autograph_is_zero((uint8_t*)data_elements, (size_t)data_size);
  (*env)->ReleaseByteArrayElements(env, data, data_elements, 0);
  return is_zero ? JNI_TRUE : JNI_FALSE;
}
