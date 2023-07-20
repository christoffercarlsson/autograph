#include "internal.h"

namespace autograph {

CertifyFunction create_certify(const Bytes our_private_key,
                               const Bytes their_public_key) {
  auto certify_function = [our_private_key, their_public_key](const Bytes data) {
    Bytes signature(64);
    int result = autograph_certify(
        signature.data(), our_private_key.data(), their_public_key.data(),
        data.data(), data.size());
    if (result != 0) {
      throw std::runtime_error("Certification failed");
    }
    return signature;
  };
  return certify_function;
}

DecryptFunction create_decrypt(const Bytes their_secret_key) {
  auto decrypt_function = [their_secret_key](const Bytes message) {
    Bytes plaintext(message.size() - 20);
    int result = autograph_decrypt(plaintext.data(), their_secret_key.data(),
                                   message.data(), message.size());
    if (result != 0) {
      throw std::runtime_error("Decryption failed");
    }
    return plaintext;
  };
  return decrypt_function;
}

class EncryptIndexCounter {
public:
    unsigned int index;

    EncryptIndexCounter() : index(0) {}

    void increment() {
        index += 1;
    }
};

EncryptFunction create_encrypt(const Bytes our_secret_key) {
  EncryptIndexCounter index_counter;
  auto encrypt_function = [our_secret_key,
                           index_counter](const Bytes plaintext) mutable {
    index_counter.increment();
    Bytes ciphertext(plaintext.size() + 20);
    int result = autograph_encrypt(ciphertext.data(), our_secret_key.data(),
                                   index_counter.index, plaintext.data(), plaintext.size());
    if (result != 0) {
      throw std::runtime_error("Encryption failed");
    }
    return ciphertext;
  };
  return encrypt_function;
}

VerifyFunction create_verify(const Bytes their_identity_key) {
  auto verify_function = [their_identity_key](
                             const Bytes certificates, const Bytes data) {
    return autograph_verify(their_identity_key.data(),
                            certificates.data(), certificates.size() / 96,
                            data.data(), data.size()) == 0;
  };
  return verify_function;
}

SessionFunction create_session(const Bytes our_private_key,
                               const Bytes their_public_key,
                               const Bytes transcript,
                               const Bytes our_secret_key,
                               const Bytes their_secret_key) {
  auto session_function = [our_private_key, their_public_key, transcript,
                           our_secret_key,
                           their_secret_key](const Bytes their_message) {
    int result =
        autograph_session(transcript.data(), their_public_key.data(),
                          their_secret_key.data(), their_message.data());
    if (result != 0) {
      throw std::runtime_error("Handshake verification failed");
    }
    auto certify =
        create_certify(our_private_key, their_public_key);
    auto decrypt = create_decrypt(their_secret_key);
    auto encrypt = create_encrypt(our_secret_key);
    auto verify = create_verify(their_public_key);
    Session session = {certify, decrypt, encrypt, verify};
    return session;
  };
  return session_function;
}

}  // namespace autograph
