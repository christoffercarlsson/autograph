#include "autograph.h"
#include "private.hpp"

namespace autograph {

CertifyFunction create_certify(const Bytes &our_private_key,
                               const Bytes &their_public_key,
                               const Bytes &their_secret_key) {
  auto certify_function = [&our_private_key, &their_public_key,
                           &their_secret_key](const Bytes &message) {
    Bytes signature(SIGNATURE_SIZE);
    bool success =
        autograph_certify(signature.data(), our_private_key.data(),
                          their_public_key.data(), their_secret_key.data(),
                          message.data(), message.size()) == 0;
    if (!success) {
      throw std::runtime_error("Certification failed");
    }
    return std::move(signature);
  };
  return std::move(certify_function);
}

DecryptFunction create_decrypt(const Bytes &their_secret_key) {
  auto decrypt_function = [&their_secret_key](const Bytes &message) {
    Bytes plaintext(message.size() - MESSAGE_EXTRA_SIZE);
    bool success = autograph_decrypt(plaintext.data(), their_secret_key.data(),
                                     message.data(), message.size()) == 0;
    if (!success) {
      throw std::runtime_error("Decryption failed");
    }
    return std::move(plaintext);
  };
  return std::move(decrypt_function);
}

EncryptFunction create_encrypt(const Bytes &our_secret_key) {
  unsigned int index = 0;
  auto encrypt_function = [&our_secret_key, &index](const Bytes &plaintext) {
    index++;
    Bytes ciphertext(plaintext.size() + MESSAGE_EXTRA_SIZE);
    bool success =
        autograph_encrypt(ciphertext.data(), our_secret_key.data(), index,
                          plaintext.data(), plaintext.size()) == 0;
    if (!success) {
      throw std::runtime_error("Encryption failed");
    }
    return std::move(ciphertext);
  };
  return std::move(encrypt_function);
}

VerifyFunction create_verify(const Bytes &their_identity_key,
                             const Bytes &their_secret_key) {
  auto verify_function = [&their_identity_key, &their_secret_key](
                             const Bytes &certificates, const Bytes &message) {
    return autograph_verify(
               their_identity_key.data(), their_secret_key.data(),
               certificates.data(),
               certificates.size() / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE),
               message.data(), message.size()) == 0;
  };
  return std::move(verify_function);
}

SessionFunction create_session(const Bytes &our_private_key,
                               const Bytes &their_public_key,
                               const Bytes &transcript,
                               const Bytes &our_secret_key,
                               const Bytes &their_secret_key) {
  auto session_function = [&our_private_key, &their_public_key, &transcript,
                           &our_secret_key,
                           &their_secret_key](const Bytes &their_message) {
    bool verified =
        autograph_session(transcript.data(), their_public_key.data(),
                          their_secret_key.data(), their_message.data()) == 0;
    if (!verified) {
      throw std::runtime_error("Handshake verification failed");
    }
    auto certify =
        create_certify(our_private_key, their_public_key, their_secret_key);
    auto decrypt = create_decrypt(their_secret_key);
    auto encrypt = create_encrypt(our_secret_key);
    auto verify = create_verify(their_public_key, their_secret_key);
    Session session = {certify, decrypt, encrypt, verify};
    return std::move(session);
  };
  return std::move(session_function);
}

}  // namespace autograph
