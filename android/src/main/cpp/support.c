#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographKeyPairSize(JNIEnv* env,
                                                              jclass class) {
  return (jint)autograph_key_pair_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographNonceSize(JNIEnv* env,
                                                            jclass class) {
  return (jint)autograph_nonce_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographPublicKeySize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_public_key_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographSafetyNumberSize(
    JNIEnv* env, jclass class) {
  return (jint)autograph_safety_number_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographSecretKeySize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_secret_key_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographSignatureSize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_signature_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographTranscriptSize(JNIEnv* env,
                                                                 jclass class) {
  return (jint)autograph_transcript_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Support_00024Companion_autographSkippedIndexesCount(
    JNIEnv* env, jclass class) {
  return (jint)autograph_skipped_indexes_count();
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Support_00024Companion_autographReady(JNIEnv* env,
                                                        jclass class) {
  bool ready = autograph_ready();
  return ready ? JNI_TRUE : JNI_FALSE;
}
