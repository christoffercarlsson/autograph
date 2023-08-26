#ifndef AUTOGRAPH_TYPES_H
#define AUTOGRAPH_TYPES_H

#ifdef __cplusplus
#include <functional>
#include <vector>

namespace Autograph {

using Bytes = std::vector<unsigned char>;

struct KeyPair {
  Bytes privateKey;
  Bytes publicKey;
};

struct KeyPairResult {
  bool success;
  KeyPair keyPair;
};

struct DecryptionResult {
  bool success;
  Bytes data;
};

struct EncryptionResult {
  bool success;
  Bytes message;
};

struct SafetyNumberResult {
  bool success;
  Bytes safetyNumber;
};

struct SignResult {
  bool success;
  Bytes signature;
};

using SignDataFunction = std::function<SignResult(const Bytes)>;

using SignIdentityFunction = std::function<SignResult()>;

using DecryptFunction = std::function<DecryptionResult(const Bytes)>;

using EncryptFunction = std::function<EncryptionResult(const Bytes)>;

using SafetyNumberFunction = std::function<SafetyNumberResult(const Bytes)>;

using VerifyDataFunction = std::function<bool(const Bytes, const Bytes)>;

using VerifyIdentityFunction = std::function<bool(const Bytes)>;

struct Session {
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  SignDataFunction signData;
  SignIdentityFunction signIdentity;
  VerifyDataFunction verifyData;
  VerifyIdentityFunction verifyIdentity;
};

struct KeyExchangeVerificationResult {
  bool success;
  Session session;
};

using KeyExchangeVerificationFunction =
    std::function<KeyExchangeVerificationResult(const Bytes)>;

struct KeyExchange {
  Bytes handshake;
  KeyExchangeVerificationFunction verify;
};

struct KeyExchangeResult {
  bool success;
  KeyExchange keyExchange;
};

using KeyExchangeFunction =
    std::function<KeyExchangeResult(KeyPair &, const Bytes, const Bytes)>;

struct Party {
  SafetyNumberFunction calculateSafetyNumber;
  KeyExchangeFunction performKeyExchange;
};

using SignFunction = std::function<SignResult(const Bytes)>;

}  // namespace Autograph
#endif

#endif
