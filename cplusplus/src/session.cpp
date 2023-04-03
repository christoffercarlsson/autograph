#include "autograph.h"
#include "private.hpp"

namespace autograph {

CertifyFunction create_certify(const unsigned char *our_private_key,
                               const unsigned char *their_public_key,
                               const unsigned char *their_secret_key) {
  auto certify_function = [our_private_key, their_public_key, their_secret_key](
                              unsigned char *signature,
                              const unsigned char *message,
                              const unsigned long long message_size) {
    return autograph_certify(signature, our_private_key, their_public_key,
                             their_secret_key, message, message_size) == 0;
  };
  return std::move(certify_function);
}

DecryptFunction create_decrypt(const unsigned char *their_secret_key) {
  auto decrypt_function =
      [their_secret_key](unsigned char *plaintext, const unsigned char *message,
                         const unsigned long long message_size) {
        return autograph_decrypt(plaintext, their_secret_key, message,
                                 message_size) == 0;
      };
  return std::move(decrypt_function);
}

EncryptFunction create_encrypt(const unsigned char *our_secret_key) {
  auto encrypt_function = [our_secret_key](
                              unsigned char *ciphertext,
                              const unsigned char *plaintext,
                              const unsigned long long plaintext_size) {
    return autograph_encrypt(ciphertext, our_secret_key, plaintext,
                             plaintext_size) == 0;
  };
  return std::move(encrypt_function);
}

VerifyFunction create_verify(const unsigned char *their_identity_key,
                             const unsigned char *their_secret_key) {
  auto verify_function = [their_identity_key, their_secret_key](
                             const unsigned char *certificates,
                             const unsigned long long certificate_count,
                             const unsigned char *message,
                             const unsigned long long message_size) {
    return autograph_verify(their_identity_key, their_secret_key, certificates,
                            certificate_count, message, message_size) == 0;
  };
  return std::move(verify_function);
}

SessionFunction create_session(const unsigned char *our_private_key,
                               const unsigned char *their_public_key,
                               const unsigned char *transcript,
                               const unsigned char *our_secret_key,
                               const unsigned char *their_secret_key) {
  auto session_function = [our_private_key, their_public_key, transcript,
                           our_secret_key, their_secret_key](
                              const unsigned char *their_ciphertext) {
    bool verified = autograph_session(transcript, their_public_key,
                                      their_secret_key, their_ciphertext) == 0;
    auto certify =
        create_certify(our_private_key, their_public_key, their_secret_key);
    auto decrypt = create_decrypt(their_secret_key);
    auto encrypt = create_encrypt(our_secret_key);
    auto verify = create_verify(their_public_key, their_secret_key);
    Session session = {certify, decrypt, encrypt, verify};
    SessionResult result = {verified, session};
    return std::move(result);
  };
  return std::move(session_function);
}

}  // namespace autograph
