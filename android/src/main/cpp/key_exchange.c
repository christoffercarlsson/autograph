#include <jni.h>

#include "autograph.h"

JNIEXPORT jint JNICALL
Java_sh_autograph_KeyExchange_00024Companion_autographTranscriptSize(
    JNIEnv* env, jclass class) {
  return (jint)autograph_transcript_size();
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_KeyExchange_00024Companion_autographKeyExchange(
    JNIEnv* env, jclass class, jbyteArray transcript, jbyteArray our_signature,
    jbyteArray sending_key, jbyteArray receiving_key, jboolean is_initiator,
    jbyteArray our_identity_key_pair, jbyteArray our_session_key_pair,
    jbyteArray their_identity_key, jbyteArray their_session_key) {
  jbyte* transcript_elements =
      (*env)->GetByteArrayElements(env, transcript, NULL);
  jbyte* our_signature_elements =
      (*env)->GetByteArrayElements(env, our_signature, NULL);
  jbyte* sending_key_elements =
      (*env)->GetByteArrayElements(env, sending_key, NULL);
  jbyte* receiving_key_elements =
      (*env)->GetByteArrayElements(env, receiving_key, NULL);
  jbyte* our_identity_key_pair_elements =
      (*env)->GetByteArrayElements(env, our_identity_key_pair, NULL);
  jbyte* our_session_key_pair_elements =
      (*env)->GetByteArrayElements(env, our_session_key_pair, NULL);
  jbyte* their_identity_key_elements =
      (*env)->GetByteArrayElements(env, their_identity_key, NULL);
  jbyte* their_session_key_elements =
      (*env)->GetByteArrayElements(env, their_session_key, NULL);
  bool success = autograph_key_exchange(
      (uint8_t*)transcript_elements, (uint8_t*)our_signature_elements,
      (uint8_t*)sending_key_elements, (uint8_t*)receiving_key_elements,
      (bool)is_initiator, (uint8_t*)our_identity_key_pair_elements,
      (uint8_t*)our_session_key_pair_elements,
      (uint8_t*)their_identity_key_elements,
      (uint8_t*)their_session_key_elements);
  (*env)->ReleaseByteArrayElements(env, transcript, transcript_elements, 0);
  (*env)->ReleaseByteArrayElements(env, our_signature, our_signature_elements,
                                   0);
  (*env)->ReleaseByteArrayElements(env, sending_key, sending_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, receiving_key, receiving_key_elements,
                                   0);
  (*env)->ReleaseByteArrayElements(env, our_identity_key_pair,
                                   our_identity_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, our_session_key_pair,
                                   our_session_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_identity_key,
                                   their_identity_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_session_key,
                                   their_session_key_elements, 0);
  return success ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_sh_autograph_KeyExchange_00024Companion_autographVerifyKeyExchange(
    JNIEnv* env, jclass class, jbyteArray transcript,
    jbyteArray our_identity_key_pair, jbyteArray their_identity_key,
    jbyteArray their_signature) {
  jbyte* transcript_elements =
      (*env)->GetByteArrayElements(env, transcript, NULL);
  jbyte* our_identity_key_pair_elements =
      (*env)->GetByteArrayElements(env, our_identity_key_pair, NULL);
  jbyte* their_identity_key_elements =
      (*env)->GetByteArrayElements(env, their_identity_key, NULL);
  jbyte* their_signature_elements =
      (*env)->GetByteArrayElements(env, their_signature, NULL);

  bool verified = autograph_verify_key_exchange(
      (uint8_t*)transcript_elements, (uint8_t*)our_identity_key_pair_elements,
      (uint8_t*)their_identity_key_elements,
      (uint8_t*)their_signature_elements);
  (*env)->ReleaseByteArrayElements(env, transcript, transcript_elements, 0);
  (*env)->ReleaseByteArrayElements(env, our_identity_key_pair,
                                   our_identity_key_pair_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_identity_key,
                                   their_identity_key_elements, 0);
  (*env)->ReleaseByteArrayElements(env, their_signature,
                                   their_signature_elements, 0);
  return verified ? JNI_TRUE : JNI_FALSE;
}
