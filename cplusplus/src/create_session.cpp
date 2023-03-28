#include "autograph/create_session.h"

#include "autograph/certify_ownership.h"
#include "autograph/constants.h"
#include "autograph/decrypt_message.h"
#include "autograph/encrypt_message.h"
#include "autograph/verify_ownership.h"
#include "autograph/verify_session.h"

CertifyFunction create_certify(const Chunk &our_private_key,
                               const Chunk &their_public_key) {
  auto certify_function = [&our_private_key,
                           &their_public_key](const Chunk &data) {
    Chunk signature(SIGNATURE_SIZE);
    bool success =
        certify_ownership(signature.data(), our_private_key.data(),
                          their_public_key.data(), data.data(), data.size());
    if (!success) {
      throw std::runtime_error("Certification failed");
    }
    return std::move(signature);
  };
  return std::move(certify_function);
}

DecryptFunction create_decrypt(const Chunk &their_secret_key) {
  auto decrypt_function = [&their_secret_key](const Chunk &message) {
    Chunk plaintext(message.size() - MESSAGE_EXTRA_SIZE);
    bool success = decrypt_message(plaintext.data(), their_secret_key.data(),
                                   message.data(), message.size());
    if (!success) {
      throw std::runtime_error("Decryption failed");
    }
    return std::move(plaintext);
  };
  return std::move(decrypt_function);
}

EncryptFunction create_encrypt(const Chunk &our_secret_key) {
  auto encrypt_function = [&our_secret_key](const Chunk &plaintext) {
    Chunk ciphertext(plaintext.size() + MESSAGE_EXTRA_SIZE);
    bool success = encrypt_message(ciphertext.data(), our_secret_key.data(),
                                   plaintext.data(), plaintext.size());
    if (!success) {
      throw std::runtime_error("Encryption failed");
    }
    return std::move(ciphertext);
  };
  return std::move(encrypt_function);
}

Chunk extract_certificates(const CertificateList &certificates) {
  Chunk result;
  for (const auto &certificate : certificates) {
    result.insert(result.end(), certificate.identity_key.begin(),
                  certificate.identity_key.end());
    result.insert(result.end(), certificate.signature.begin(),
                  certificate.signature.end());
  }
  return std::move(result);
}

VerifyFunction create_verify(const Chunk &their_identity_key,
                             const Chunk &their_secret_key) {
  auto verify_function = [&their_identity_key, &their_secret_key](
                             const CertificateList &certificates,
                             const Chunk &message) {
    return verify_ownership(their_identity_key.data(), their_secret_key.data(),
                            extract_certificates(certificates).data(),
                            certificates.size(), message.data(),
                            message.size());
  };
  return std::move(verify_function);
}

SessionFunction create_session(const Chunk &our_private_key,
                               const Chunk &their_identity_key,
                               const Chunk &transcript,
                               const Chunk &our_secret_key,
                               const Chunk &their_secret_key) {
  auto session_function = [&our_private_key, &their_identity_key, &transcript,
                           &our_secret_key,
                           &their_secret_key](const Chunk &ciphertext) {
    bool verified = verify_session(transcript.data(), their_identity_key.data(),
                                   their_secret_key.data(), ciphertext.data());
    if (!verified) {
      throw std::runtime_error("Handshake verification failed");
    }
    auto certify = create_certify(our_private_key, their_identity_key);
    auto decrypt = create_decrypt(their_secret_key);
    auto encrypt = create_encrypt(our_secret_key);
    auto verify = create_verify(their_identity_key, their_secret_key);
    Session session = {certify, decrypt, encrypt, verify};
    return std::move(session);
  };
  return std::move(session_function);
}
