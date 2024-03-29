#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographHelloSize(JNIEnv* env,
                                                            jclass class) {
  return (jint)autograph_hello_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographPublicKeySize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_public_key_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographSafetyNumberSize(
    JNIEnv* env, jclass class) {
  return (jint)autograph_safety_number_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographSecretKeySize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_secret_key_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographSignatureSize(JNIEnv* env,
                                                                jclass class) {
  return (jint)autograph_signature_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographStateSize(JNIEnv* env,
                                                            jclass class) {
  return (jint)autograph_state_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographIndexSize(JNIEnv* env,
                                                            jclass class) {
  return (jint)autograph_index_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographSizeSize(JNIEnv* env,
                                                           jclass class) {
  return (jint)autograph_size_size();
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographCiphertextSize(
    JNIEnv* env, jclass class, jint plaintext_size) {
  size_t size = autograph_ciphertext_size((size_t)plaintext_size);
  return (jint)size;
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographPlaintextSize(
    JNIEnv* env, jclass class, jint ciphertext_size) {
  size_t size = autograph_plaintext_size((size_t)ciphertext_size);
  return (jint)size;
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographSessionSize(
    JNIEnv* env, jclass class, jbyteArray state) {
  jbyte* elements = (*env)->GetByteArrayElements(env, state, NULL);
  size_t size = autograph_session_size((uint8_t*)elements);
  (*env)->ReleaseByteArrayElements(env, state, elements, 0);
  return (jint)size;
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographReadIndex(JNIEnv* env,
                                                            jclass class,
                                                            jbyteArray index) {
  jbyte* elements = (*env)->GetByteArrayElements(env, index, NULL);
  size_t size = autograph_read_index((uint8_t*)elements);
  (*env)->ReleaseByteArrayElements(env, index, elements, 0);
  return (jint)size;
}

JNIEXPORT jint JNICALL
Java_sh_autograph_Channel_00024Companion_autographReadSize(JNIEnv* env,
                                                           jclass class,
                                                           jbyteArray size) {
  jbyte* elements = (*env)->GetByteArrayElements(env, size, NULL);
  size_t s = autograph_read_size((uint8_t*)elements);
  (*env)->ReleaseByteArrayElements(env, size, elements, 0);
  return (jint)s;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographUseKeyPairs(
    JNIEnv* env, jclass class, jbyteArray public_keys, jbyteArray state,
    jbyteArray identity_key_pair, jbyteArray ephemeral_key_pair) {
  jbyte* public_keys_elements =
      (*env)->GetByteArrayElements(env, public_keys, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* identity_key_pair_elements =
      (*env)->GetByteArrayElements(env, identity_key_pair, NULL);
  jbyte* ephemeral_key_pair_elements =
      (*env)->GetByteArrayElements(env, ephemeral_key_pair, NULL);
  bool success = autograph_use_key_pairs((uint8_t*)public_keys_elements,
                                         (uint8_t*)state_elements,
                                         (uint8_t*)identity_key_pair_elements,
                                         (uint8_t*)ephemeral_key_pair_elements);
  (*env)->ReleaseByteArrayElements(env, public_keys, public_keys_elements, 0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, identity_key_pair,
                                   identity_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, ephemeral_key_pair,
                                   ephemeral_key_pair_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_sh_autograph_Channel_00024Companion_autographUsePublicKeys(
    JNIEnv* env, jclass class, jbyteArray state, jbyteArray public_keys) {
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* public_keys_elements =
      (*env)->GetByteArrayElements(env, public_keys, NULL);
  autograph_use_public_keys((uint8_t*)state_elements,
                            (uint8_t*)public_keys_elements);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, public_keys, public_keys_elements, 0);
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographAuthenticate(
    JNIEnv* env, jclass class, jbyteArray safety_number, jbyteArray state) {
  jbyte* safety_number_elements =
      (*env)->GetByteArrayElements(env, safety_number, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  bool success = autograph_authenticate((uint8_t*)safety_number_elements,
                                        (uint8_t*)state_elements);
  (*env)->ReleaseByteArrayElements(env, safety_number, safety_number_elements,
                                   0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographKeyExchange(
    JNIEnv* env, jclass class, jbyteArray signature, jbyteArray state,
    jboolean is_initiator) {
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  bool success =
      autograph_key_exchange((uint8_t*)signature_elements,
                             (uint8_t*)state_elements, (bool)is_initiator);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographVerifyKeyExchange(
    JNIEnv* env, jclass class, jbyteArray state, jbyteArray signature) {
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  bool success = autograph_verify_key_exchange((uint8_t*)state_elements,
                                               (uint8_t*)signature_elements);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographEncryptMessage(
    JNIEnv* env, jclass class, jbyteArray ciphertext, jbyteArray index,
    jbyteArray state, jbyteArray plaintext) {
  jbyte* ciphertext_elements =
      (*env)->GetByteArrayElements(env, ciphertext, NULL);
  jbyte* index_elements = (*env)->GetByteArrayElements(env, index, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* plaintext_elements =
      (*env)->GetByteArrayElements(env, plaintext, NULL);
  jsize plaintext_size = (*env)->GetArrayLength(env, plaintext);
  bool success = autograph_encrypt_message(
      (uint8_t*)ciphertext_elements, (uint8_t*)index_elements,
      (uint8_t*)state_elements, (uint8_t*)plaintext_elements,
      (size_t)plaintext_size);
  (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_elements, 0);
  (*env)->ReleaseByteArrayElements(env, index, index_elements, 0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, plaintext, plaintext_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographDecryptMessage(
    JNIEnv* env, jclass class, jbyteArray plaintext, jbyteArray plaintext_size,
    jbyteArray index, jbyteArray state, jbyteArray ciphertext) {
  jbyte* plaintext_elements =
      (*env)->GetByteArrayElements(env, plaintext, NULL);
  jbyte* plaintext_size_elements =
      (*env)->GetByteArrayElements(env, plaintext_size, NULL);
  jbyte* index_elements = (*env)->GetByteArrayElements(env, index, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* ciphertext_elements =
      (*env)->GetByteArrayElements(env, ciphertext, NULL);
  jsize ciphertext_size = (*env)->GetArrayLength(env, ciphertext);
  bool success = autograph_decrypt_message(
      (uint8_t*)plaintext_elements, (uint8_t*)plaintext_size_elements,
      (uint8_t*)index_elements, (uint8_t*)state_elements,
      (uint8_t*)ciphertext_elements, (size_t)ciphertext_size);
  (*env)->ReleaseByteArrayElements(env, plaintext, plaintext_elements, 0);
  (*env)->ReleaseByteArrayElements(env, plaintext_size, plaintext_size_elements,
                                   0);
  (*env)->ReleaseByteArrayElements(env, index, index_elements, 0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographCertifyData(
    JNIEnv* env, jclass class, jbyteArray signature, jbyteArray state,
    jbyteArray data) {
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* data_elements = (*env)->GetByteArrayElements(env, data, NULL);
  jsize data_size = (*env)->GetArrayLength(env, data);
  bool success = autograph_certify_data(
      (uint8_t*)signature_elements, (uint8_t*)state_elements,
      (uint8_t*)data_elements, (size_t)data_size);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, data, data_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographCertifyIdentity(
    JNIEnv* env, jclass class, jbyteArray signature, jbyteArray state) {
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  bool success = autograph_certify_identity((uint8_t*)signature_elements,
                                            (uint8_t*)state_elements);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographVerifyData(
    JNIEnv* env, jclass class, jbyteArray state, jbyteArray data,
    jbyteArray public_key, jbyteArray signature) {
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* data_elements = (*env)->GetByteArrayElements(env, data, NULL);
  jsize data_size = (*env)->GetArrayLength(env, data);
  jbyte* public_key_elements =
      (*env)->GetByteArrayElements(env, public_key, NULL);
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  bool verified = autograph_verify_data(
      (uint8_t*)state_elements, (uint8_t*)data_elements, (size_t)data_size,
      (uint8_t*)public_key_elements, (uint8_t*)signature_elements);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, data, data_elements, 0);
  (*env)->ReleaseByteArrayElements(env, public_key, public_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  return verified ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographVerifyIdentity(
    JNIEnv* env, jclass class, jbyteArray state, jbyteArray public_key,
    jbyteArray signature) {
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* public_key_elements =
      (*env)->GetByteArrayElements(env, public_key, NULL);
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  bool verified = autograph_verify_identity((uint8_t*)state_elements,
                                            (uint8_t*)public_key_elements,
                                            (uint8_t*)signature_elements);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, public_key, public_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  return verified ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographCloseSession(
    JNIEnv* env, jclass class, jbyteArray key, jbyteArray ciphertext,
    jbyteArray state) {
  jbyte* key_elements = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte* ciphertext_elements =
      (*env)->GetByteArrayElements(env, ciphertext, NULL);
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  bool success = autograph_close_session((uint8_t*)key_elements,
                                         (uint8_t*)ciphertext_elements,
                                         (uint8_t*)state_elements);
  (*env)->ReleaseByteArrayElements(env, key, key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_elements, 0);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Channel_00024Companion_autographOpenSession(
    JNIEnv* env, jclass class, jbyteArray state, jbyteArray key,
    jbyteArray ciphertext) {
  jbyte* state_elements = (*env)->GetByteArrayElements(env, state, NULL);
  jbyte* key_elements = (*env)->GetByteArrayElements(env, key, NULL);
  jbyte* ciphertext_elements =
      (*env)->GetByteArrayElements(env, ciphertext, NULL);
  jsize ciphertext_size = (*env)->GetArrayLength(env, ciphertext);
  bool success = autograph_open_session(
      (uint8_t*)state_elements, (uint8_t*)key_elements,
      (uint8_t*)ciphertext_elements, (size_t)ciphertext_size);
  (*env)->ReleaseByteArrayElements(env, state, state_elements, 0);
  (*env)->ReleaseByteArrayElements(env, key, key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, ciphertext, ciphertext_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}
