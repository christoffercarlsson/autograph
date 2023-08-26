#include "session.h"

#include "private.h"

namespace Autograph {

SignDataFunction createSignData(const SignFunction sign,
                                const Bytes theirPublicKey) {
  auto signDataFunction = [sign, theirPublicKey](const Bytes data) {
    Bytes subject(autograph_subject_size(data.size()));
    autograph_subject(subject.data(), theirPublicKey.data(), data.data(),
                      data.size());
    auto signResult = sign(subject);
    SignResult result = {signResult.success, signResult.signature};
    return result;
  };
  return signDataFunction;
}

SignIdentityFunction createSignIdentity(const SignFunction sign,
                                        const Bytes theirPublicKey) {
  auto signIdentityFunction = [sign, theirPublicKey]() {
    auto signResult = sign(theirPublicKey);
    SignResult result = {signResult.success, signResult.signature};
    return result;
  };
  return signIdentityFunction;
}

DecryptFunction createDecrypt(const Bytes theirSecretKey) {
  auto decryptFunction = [theirSecretKey](const Bytes message) {
    Bytes plaintext(message.size() - 24);
    bool success = autograph_decrypt(plaintext.data(), theirSecretKey.data(),
                                     message.data(), message.size()) == 0;
    DecryptionResult result = {success, plaintext};
    return result;
  };
  return decryptFunction;
}

class EncryptionIndexCounter {
 public:
  unsigned long long index;

  EncryptionIndexCounter() : index(0) {}

  void increment() { index += 1; }
};

EncryptFunction createEncrypt(const Bytes ourSecretKey) {
  EncryptionIndexCounter indexCounter;
  auto encryptFunction = [ourSecretKey,
                          indexCounter](const Bytes plaintext) mutable {
    indexCounter.increment();
    Bytes ciphertext(plaintext.size() + 24);
    bool success = autograph_encrypt(ciphertext.data(), ourSecretKey.data(),
                                     indexCounter.index, plaintext.data(),
                                     plaintext.size()) == 0;
    EncryptionResult result = {success, ciphertext};
    return result;
  };
  return encryptFunction;
}

VerifyDataFunction createVerifyData(const Bytes theirIdentityKey) {
  auto verifyDataFunction = [theirIdentityKey](const Bytes certificates,
                                               const Bytes data) {
    return autograph_verify_data(theirIdentityKey.data(), certificates.data(),
                                 certificates.size() / 96, data.data(),
                                 data.size()) == 0;
  };
  return verifyDataFunction;
}

VerifyIdentityFunction createVerifyIdentity(const Bytes theirIdentityKey) {
  auto verifyIdentityFunction = [theirIdentityKey](const Bytes certificates) {
    return autograph_verify_identity(theirIdentityKey.data(),
                                     certificates.data(),
                                     certificates.size() / 96) == 0;
  };
  return verifyIdentityFunction;
}

}  // namespace Autograph
