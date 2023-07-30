#include "session.h"

#include "private.h"

namespace autograph {

CertifyFunction create_certify(const SignFunction sign,
                               const Bytes their_public_key) {
  auto certify_function = [sign, their_public_key](const Bytes data) {
    Bytes subject(autograph_subject_size(data.size()));
    autograph_subject(subject.data(), their_public_key.data(), data.data(),
                      data.size());
    auto sign_result = sign(subject);
    CertificationResult result = {sign_result.success, sign_result.signature};
    return result;
  };
  return certify_function;
}

DecryptFunction create_decrypt(const Bytes their_secret_key) {
  auto decrypt_function = [their_secret_key](const Bytes message) {
    Bytes plaintext(message.size() - 20);
    bool success = autograph_decrypt(plaintext.data(), their_secret_key.data(),
                                     message.data(), message.size()) == 0;
    DecryptionResult result = {success, plaintext};
    return result;
  };
  return decrypt_function;
}

class EncryptIndexCounter {
 public:
  unsigned int index;

  EncryptIndexCounter() : index(0) {}

  void increment() { index += 1; }
};

EncryptFunction create_encrypt(const Bytes our_secret_key) {
  EncryptIndexCounter index_counter;
  auto encrypt_function = [our_secret_key,
                           index_counter](const Bytes plaintext) mutable {
    index_counter.increment();
    Bytes ciphertext(plaintext.size() + 20);
    bool success = autograph_encrypt(ciphertext.data(), our_secret_key.data(),
                                     index_counter.index, plaintext.data(),
                                     plaintext.size()) == 0;
    EncryptionResult result = {success, ciphertext};
    return result;
  };
  return encrypt_function;
}

VerifyFunction create_verify(const Bytes their_identity_key) {
  auto verify_function = [their_identity_key](const Bytes certificates,
                                              const Bytes data) {
    return autograph_verify(their_identity_key.data(), certificates.data(),
                            certificates.size() / 96, data.data(),
                            data.size()) == 0;
  };
  return verify_function;
}

SessionFunction create_session(const SignFunction sign,
                               const Bytes their_public_key,
                               const Bytes transcript,
                               const Bytes our_secret_key,
                               const Bytes their_secret_key) {
  auto session_function = [sign, their_public_key, transcript, our_secret_key,
                           their_secret_key](const Bytes their_message) {
    bool success =
        autograph_session(transcript.data(), their_public_key.data(),
                          their_secret_key.data(), their_message.data()) == 0;
    auto certify = create_certify(sign, their_public_key);
    auto decrypt = create_decrypt(their_secret_key);
    auto encrypt = create_encrypt(our_secret_key);
    auto verify = create_verify(their_public_key);
    Session session = {certify, decrypt, encrypt, verify};
    SessionResult result = {success, session};
    return result;
  };
  return session_function;
}

}  // namespace autograph
