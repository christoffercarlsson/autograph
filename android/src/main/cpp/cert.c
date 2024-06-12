#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_Cert_00024Companion_autographSignatureSize(JNIEnv* env,
                                                             jclass class) {
  return (jint)autograph_signature_size();
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Cert_00024Companion_autographCertify(
    JNIEnv* env, jclass class, jbyteArray signature,
    jbyteArray our_identity_key_pair, jbyteArray their_identity_key,
    jbyteArray data) {
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  jbyte* our_identity_key_pair_elements =
      (*env)->GetByteArrayElements(env, our_identity_key_pair, NULL);
  jbyte* their_identity_key_elements =
      (*env)->GetByteArrayElements(env, their_identity_key, NULL);
  jbyte* data_elements = (*env)->GetByteArrayElements(env, data, NULL);
  jsize data_size = (*env)->GetArrayLength(env, data);
  bool success = autograph_certify((uint8_t*)signature_elements,
                                   (uint8_t*)our_identity_key_pair_elements,
                                   (uint8_t*)their_identity_key_elements,
                                   (uint8_t*)data_elements, (size_t)data_size);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  (*env)->ReleaseByteArrayElements(env, our_identity_key_pair,
                                   our_identity_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_identity_key,
                                   their_identity_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, data, data_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_Cert_00024Companion_autographVerify(
    JNIEnv* env, jclass class, jbyteArray owner_identity_key,
    jbyteArray certifier_identity_key, jbyteArray signature, jbyteArray data) {
  jbyte* owner_identity_key_elements =
      (*env)->GetByteArrayElements(env, owner_identity_key, NULL);
  jbyte* certifier_identity_key_elements =
      (*env)->GetByteArrayElements(env, certifier_identity_key, NULL);
  jbyte* signature_elements =
      (*env)->GetByteArrayElements(env, signature, NULL);
  jbyte* data_elements = (*env)->GetByteArrayElements(env, data, NULL);
  jsize data_size = (*env)->GetArrayLength(env, data);
  bool verified = autograph_verify((uint8_t*)owner_identity_key_elements,
                                   (uint8_t*)certifier_identity_key_elements,
                                   (uint8_t*)signature_elements,
                                   (uint8_t*)data_elements, (size_t)data_size);
  (*env)->ReleaseByteArrayElements(env, owner_identity_key,
                                   owner_identity_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, certifier_identity_key,
                                   certifier_identity_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, signature, signature_elements, 0);
  (*env)->ReleaseByteArrayElements(env, data, data_elements, 0);
  return verified ? JNI_TRUE : JNI_FALSE;
}
