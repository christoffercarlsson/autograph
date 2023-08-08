#include "session.h"

#include "private.h"

namespace Autograph {

CertifyFunction createCertify(const SignFunction sign,
                              const Bytes theirPublicKey) {
  auto certifyFunction = [sign, theirPublicKey](const Bytes data) {
    Bytes subject(autograph_subject_size(data.size()));
    autograph_subject(subject.data(), theirPublicKey.data(), data.data(),
                      data.size());
    auto signResult = sign(subject);
    CertificationResult result = {signResult.success, signResult.signature};
    return result;
  };
  return certifyFunction;
}

DecryptFunction createDecrypt(const Bytes theirSecretKey) {
  auto decryptFunction = [theirSecretKey](const Bytes message) {
    Bytes plaintext(message.size() - 20);
    bool success = autograph_decrypt(plaintext.data(), theirSecretKey.data(),
                                     message.data(), message.size()) == 0;
    DecryptionResult result = {success, plaintext};
    return result;
  };
  return decryptFunction;
}

class EncryptIndexCounter {
 public:
  unsigned int index;

  EncryptIndexCounter() : index(0) {}

  void increment() { index += 1; }
};

EncryptFunction createEncrypt(const Bytes ourSecretKey) {
  EncryptIndexCounter indexCounter;
  auto encryptFunction = [ourSecretKey,
                          indexCounter](const Bytes plaintext) mutable {
    indexCounter.increment();
    Bytes ciphertext(plaintext.size() + 20);
    bool success = autograph_encrypt(ciphertext.data(), ourSecretKey.data(),
                                     indexCounter.index, plaintext.data(),
                                     plaintext.size()) == 0;
    EncryptionResult result = {success, ciphertext};
    return result;
  };
  return encryptFunction;
}

VerifyFunction createVerify(const Bytes theirIdentityKey) {
  auto verifyFunction = [theirIdentityKey](const Bytes certificates,
                                           const Bytes data) {
    return autograph_verify(theirIdentityKey.data(), certificates.data(),
                            certificates.size() / 96, data.data(),
                            data.size()) == 0;
  };
  return verifyFunction;
}

SessionFunction createSession(const SignFunction sign,
                              const Bytes theirPublicKey,
                              const Bytes transcript, const Bytes ourSecretKey,
                              const Bytes theirSecretKey) {
  auto sessionFunction = [sign, theirPublicKey, transcript, ourSecretKey,
                          theirSecretKey](const Bytes theirMessage) {
    bool success =
        autograph_session(transcript.data(), theirPublicKey.data(),
                          theirSecretKey.data(), theirMessage.data()) == 0;
    auto certify = createCertify(sign, theirPublicKey);
    auto decrypt = createDecrypt(theirSecretKey);
    auto encrypt = createEncrypt(ourSecretKey);
    auto verify = createVerify(theirPublicKey);
    Session session = {certify, decrypt, encrypt, verify};
    SessionResult result = {success, session};
    return result;
  };
  return sessionFunction;
}

}  // namespace Autograph
