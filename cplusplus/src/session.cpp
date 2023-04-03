#include "autograph/session.h"

#include "autograph/core/message.h"
#include "autograph/core/ownership.h"
#include "autograph/core/session.h"
#include "autograph/crypto/sign.h"

namespace autograph {

CertifyFunction create_session_certify(const unsigned char *our_private_key,
                                       const unsigned char *their_public_key) {
  auto certify_function = [our_private_key, their_public_key](
                              unsigned char *signature,
                              const unsigned char *data,
                              const unsigned long long data_size) {
    int result = autograph_core_ownership_certify(
        signature, our_private_key, their_public_key, data, data_size);
    if (result != 0) {
      throw std::runtime_error("Certification failed");
    }
  };
  return std::move(certify_function);
}

DecryptFunction create_session_decrypt(const unsigned char *their_secret_key) {
  auto decrypt_function =
      [their_secret_key](unsigned char *plaintext, const unsigned char *message,
                         const unsigned long long message_size) {
        int result = autograph_core_message_decrypt(plaintext, their_secret_key,
                                                    message, message_size);
        if (result != 0) {
          throw std::runtime_error("Decryption failed");
        }
      };
  return std::move(decrypt_function);
}

EncryptFunction create_session_encrypt(const unsigned char *our_secret_key) {
  auto encrypt_function = [our_secret_key](
                              unsigned char *ciphertext,
                              const unsigned char *plaintext,
                              const unsigned long long plaintext_size) {
    int result = autograph_core_message_encrypt(ciphertext, our_secret_key,
                                                plaintext, plaintext_size);
    if (result != 0) {
      throw std::runtime_error("Encryption failed");
    }
  };
  return std::move(encrypt_function);
}

VerifyFunction create_session_verify(const unsigned char *their_identity_key,
                                     const unsigned char *their_secret_key) {
  auto verify_function = [their_identity_key, their_secret_key](
                             const unsigned char *certificates,
                             const unsigned long long certificate_count,
                             const unsigned char *message,
                             const unsigned long long message_size) {
    int result = autograph_core_ownership_verify(
        their_identity_key, their_secret_key, certificates, certificate_count,
        message, message_size);
    return result == 0;
  };
  return std::move(verify_function);
}

SessionFunction create_session(const unsigned char *our_private_key,
                               const unsigned char *their_identity_key,
                               const unsigned char *transcript,
                               const unsigned char *our_secret_key,
                               const unsigned char *their_secret_key) {
  auto session_function = [our_private_key, their_identity_key, transcript,
                           our_secret_key, their_secret_key](
                              const unsigned char *their_ciphertext) {
    int result = autograph_core_session(transcript, their_identity_key,
                                        their_secret_key, their_ciphertext);
    if (result != 0) {
      throw std::runtime_error("Handshake verification failed");
    }
    auto certify = create_session_certify(our_private_key, their_identity_key);
    auto decrypt = create_session_decrypt(their_secret_key);
    auto encrypt = create_session_encrypt(our_secret_key);
    auto verify = create_session_verify(their_identity_key, their_secret_key);
    Session session = {certify, decrypt, encrypt, verify};
    return std::move(session);
  };
  return std::move(session_function);
}

}  // namespace autograph
