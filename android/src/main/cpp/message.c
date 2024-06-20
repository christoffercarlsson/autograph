#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_Message_00024Companion_autographSecretKeySize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_secret_key_size();
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Message_00024Companion_autographGenerateSecretKey(
    JNIEnv* env, jclass class, jbyteArray key) {
  jbyte* elements = (*env)->GetByteArrayElements(env, key, NULL);
  bool success = autograph_generate_secret_key((uint8_t*)elements);
  (*env)->ReleaseByteArrayElements(env, key, elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Message_00024Companion_autographNonceSize(JNIEnv* env,
                                                            jclass class) {
  return (jint)autograph_nonce_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Message_00024Companion_autographSkippedIndexesSize(
    JNIEnv* env, jclass class, jint count) {
  return (jint)autograph_skipped_indexes_size((uint16_t)count);
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Message_00024Companion_autographCiphertextSize(
    JNIEnv* env, jclass class, jint plaintext_size) {
  size_t size = autograph_ciphertext_size((size_t)plaintext_size);
  return (jint)size;
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Message_00024Companion_autographPlaintextSize(
    JNIEnv* env, jclass class, jint ciphertext_size) {
  size_t size = autograph_plaintext_size((size_t)ciphertext_size);
  return (jint)size;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Message_00024Companion_autographEncrypt(
    JNIEnv* env, jclass class, jintArray index, jbyteArray ciphertext,
    jbyteArray key, jbyteArray nonce, jbyteArray plaintext) {
  jint* index_elements = (*env)->GetIntArrayElements(env, index, NULL);
  jbyte* ciphertext_elements =
      (*env)->GetByteArrayElements(env, ciphertext, NULL);
  jbyte* key_elements = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte* nonce_elements = (*env)->GetByteArrayElements(env, nonce, NULL);
  jbyte* plaintext_elements =
      (*env)->GetByteArrayElements(env, plaintext, NULL);
  jsize plaintext_size = (*env)->GetArrayLength(env, plaintext);
  bool success = autograph_encrypt(
      (uint32_t*)index_elements, (uint8_t*)ciphertext_elements,
      (uint8_t*)key_elements, (uint8_t*)nonce_elements,
      (uint8_t*)plaintext_elements, (size_t)plaintext_size);
  (*env)->ReleaseIntArrayElements(env, index, index_elements, 0);
  (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_elements, 0);
  (*env)->ReleaseByteArrayElements(env, key, key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_elements, 0);
  (*env)->ReleaseByteArrayElements(env, plaintext, plaintext_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Message_00024Companion_autographDecrypt(
    JNIEnv* env, jclass class, jintArray index, jbyteArray plaintext,
    jintArray plaintext_size, jbyteArray key, jbyteArray nonce,
    jbyteArray skipped_indexes, jbyteArray ciphertext) {
  jint* index_elements = (*env)->GetIntArrayElements(env, index, NULL);
  jbyte* plaintext_elements =
      (*env)->GetByteArrayElements(env, plaintext, NULL);
  jint* plaintext_size_elements =
      (*env)->GetIntArrayElements(env, plaintext_size, NULL);
  jbyte* key_elements = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte* nonce_elements = (*env)->GetByteArrayElements(env, nonce, NULL);
  jbyte* skipped_indexes_elements =
      (*env)->GetByteArrayElements(env, skipped_indexes, NULL);
  jsize skipped_indexes_size = (*env)->GetArrayLength(env, skipped_indexes);
  jbyte* ciphertext_elements =
      (*env)->GetByteArrayElements(env, ciphertext, NULL);
  jsize ciphertext_size = (*env)->GetArrayLength(env, ciphertext);
  bool success = autograph_decrypt(
      (uint32_t*)index_elements, (uint8_t*)plaintext_elements,
      (size_t*)plaintext_size_elements, (uint8_t*)key_elements,
      (uint8_t*)nonce_elements, (uint8_t*)skipped_indexes_elements,
      (size_t)skipped_indexes_size, (uint8_t*)ciphertext_elements,
      (size_t)ciphertext_size);
  (*env)->ReleaseIntArrayElements(env, index, index_elements, 0);
  (*env)->ReleaseByteArrayElements(env, plaintext, plaintext_elements, 0);
  (*env)->ReleaseIntArrayElements(env, plaintext_size, plaintext_size_elements,
                                  0);
  (*env)->ReleaseByteArrayElements(env, key, key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, nonce, nonce_elements, 0);
  (*env)->ReleaseByteArrayElements(env, skipped_indexes,
                                   skipped_indexes_elements, 0);
  (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}
