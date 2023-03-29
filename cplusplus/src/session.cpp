#include "autograph/session.h"

#include "autograph/core/message.h"
#include "autograph/core/ownership.h"
#include "autograph/core/session.h"
#include "autograph/crypto/sign.h"

namespace autograph {

CertifyFunction session_create_certify(const Chunk &our_private_key,
                                       const Chunk &their_public_key) {
  auto certify_function = [&our_private_key,
                           &their_public_key](const Chunk &data) {
    Chunk signature(autograph_crypto_sign_SIGNATURE_SIZE);
    int result = autograph_core_ownership_certify(
        signature.data(), our_private_key.data(), their_public_key.data(),
        data.data(), data.size());
    if (result != 0) {
      throw std::runtime_error("Certification failed");
    }
    return std::move(signature);
  };
  return std::move(certify_function);
}

DecryptFunction session_create_decrypt(const Chunk &their_secret_key) {
  auto decrypt_function = [&their_secret_key](const Chunk &message) {
    Chunk plaintext(message.size() - autograph_core_message_EXTRA_SIZE);
    int result = autograph_core_message_decrypt(plaintext.data(),
                                                their_secret_key.data(),
                                                message.data(), message.size());
    if (result != 0) {
      throw std::runtime_error("Decryption failed");
    }
    return std::move(plaintext);
  };
  return std::move(decrypt_function);
}

EncryptFunction session_create_encrypt(const Chunk &our_secret_key) {
  auto encrypt_function = [&our_secret_key](const Chunk &plaintext) {
    Chunk ciphertext(plaintext.size() + autograph_core_message_EXTRA_SIZE);
    int result =
        autograph_core_message_encrypt(ciphertext.data(), our_secret_key.data(),
                                       plaintext.data(), plaintext.size());
    if (result != 0) {
      throw std::runtime_error("Encryption failed");
    }
    return std::move(ciphertext);
  };
  return std::move(encrypt_function);
}

Chunk session_extract_certificates(const CertificateList &certificates) {
  Chunk result;
  for (const auto &certificate : certificates) {
    result.insert(result.end(), certificate.identity_key.begin(),
                  certificate.identity_key.end());
    result.insert(result.end(), certificate.signature.begin(),
                  certificate.signature.end());
  }
  return std::move(result);
}

VerifyFunction session_create_verify(const Chunk &their_identity_key,
                                     const Chunk &their_secret_key) {
  auto verify_function = [&their_identity_key, &their_secret_key](
                             const CertificateList &certificates,
                             const Chunk &message) {
    int result = autograph_core_ownership_verify(
        their_identity_key.data(), their_secret_key.data(),
        session_extract_certificates(certificates).data(), certificates.size(),
        message.data(), message.size());
    return result == 0;
  };
  return std::move(verify_function);
}

SessionFunction session_create(const Chunk &our_private_key,
                               const Chunk &their_identity_key,
                               const Chunk &transcript,
                               const Chunk &our_secret_key,
                               const Chunk &their_secret_key) {
  auto session_function = [&our_private_key, &their_identity_key, &transcript,
                           &our_secret_key,
                           &their_secret_key](const Chunk &ciphertext) {
    int result =
        autograph_core_session(transcript.data(), their_identity_key.data(),
                               their_secret_key.data(), ciphertext.data());
    if (result != 0) {
      throw std::runtime_error("Handshake verification failed");
    }
    auto certify = session_create_certify(our_private_key, their_identity_key);
    auto decrypt = session_create_decrypt(their_secret_key);
    auto encrypt = session_create_encrypt(our_secret_key);
    auto verify = session_create_verify(their_identity_key, their_secret_key);
    Session session = {certify, decrypt, encrypt, verify};
    return std::move(session);
  };
  return std::move(session_function);
}

}  // namespace autograph
