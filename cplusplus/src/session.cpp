#include "session.h"

#include "numbers.h"
#include "private.h"
#include "sizes.h"

namespace Autograph {

SignDataFunction createSignData(const SignFunction sign,
                                const Bytes theirPublicKey) {
  auto signDataFunction = [sign, theirPublicKey](const Bytes data) {
    Bytes subject(data.size() + 32);
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

DecryptFunction createDecrypt(Bytes theirSecretKey) {
  Bytes messageIndex(8);
  Bytes decryptIndex(8);
  Bytes plaintextSize(4);
  Bytes skippedKeys(40002);
  auto decryptFunction = [theirSecretKey, messageIndex, decryptIndex,
                          skippedKeys,
                          plaintextSize](const Bytes message) mutable {
    Bytes plaintext(autograph_plaintext_size(message.size()));
    bool success = autograph_decrypt(plaintext.data(), plaintextSize.data(),
                                     messageIndex.data(), decryptIndex.data(),
                                     skippedKeys.data(), theirSecretKey.data(),
                                     message.data(), message.size()) == 0;
    if (success) {
      plaintext.resize(autograph_read_uint32(plaintextSize.data()));
    }
    DecryptionResult result = {
        success, autograph_read_uint64(messageIndex.data()), plaintext};
    return result;
  };
  return decryptFunction;
}

EncryptFunction createEncrypt(Bytes ourSecretKey) {
  Bytes index(8);
  auto encryptFunction = [ourSecretKey, index](const Bytes plaintext) mutable {
    Bytes ciphertext(autograph_ciphertext_size(plaintext.size()));
    bool success =
        autograph_encrypt(ciphertext.data(), index.data(), ourSecretKey.data(),
                          plaintext.data(), plaintext.size()) == 0;
    EncryptionResult result = {success, autograph_read_uint64(index.data()),
                               ciphertext};
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
