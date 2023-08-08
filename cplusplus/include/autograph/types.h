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

struct CertificationResult {
  bool success;
  Bytes signature;
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

using CertifyFunction = std::function<CertificationResult(const Bytes)>;

using DecryptFunction = std::function<DecryptionResult(const Bytes)>;

using EncryptFunction = std::function<EncryptionResult(const Bytes)>;

using SafetyNumberFunction = std::function<SafetyNumberResult(const Bytes)>;

using VerifyFunction = std::function<bool(const Bytes, const Bytes)>;

struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

struct SessionResult {
  bool success;
  Session session;
};

using SessionFunction = std::function<SessionResult(const Bytes)>;

struct Handshake {
  Bytes message;
  SessionFunction establishSession;
};

struct HandshakeResult {
  bool success;
  Handshake handshake;
};

using HandshakeFunction =
    std::function<HandshakeResult(KeyPair &, const Bytes, const Bytes)>;

struct Party {
  SafetyNumberFunction calculateSafetyNumber;
  HandshakeFunction performHandshake;
};

struct SignResult {
  bool success;
  Bytes signature;
};

using SignFunction = std::function<SignResult(const Bytes)>;

}  // namespace Autograph
#endif

#endif
