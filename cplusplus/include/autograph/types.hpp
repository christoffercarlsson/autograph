#pragma once

#include <functional>

namespace autograph {

using Handshake = unsigned char[80];

using PrivateKey = unsigned char[32];

using PublicKey = unsigned char[32];

using SafetyNumber = unsigned char[60];

using Signature = unsigned char[64];

using CertifyFunction = std::function<bool(
    unsigned char *, const unsigned char *, const unsigned long long)>;

using DecryptFunction = std::function<bool(
    unsigned char *, const unsigned char *, const unsigned long long)>;

using EncryptFunction = std::function<bool(
    unsigned char *, const unsigned char *, const unsigned long long)>;

using SafetyNumberFunction =
    std::function<bool(unsigned char *, const unsigned char *)>;

using VerifyFunction =
    std::function<bool(const unsigned char *, const unsigned long long,
                       const unsigned char *, const unsigned long long)>;

struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

using SessionResult = std::pair<bool, Session>;

using SessionFunction = std::function<SessionResult(const unsigned char *)>;

using HandshakeResult = std::pair<bool, SessionFunction>;

using HandshakeFunction = std::function<HandshakeResult(
    unsigned char *, const unsigned char *, const unsigned char *)>;

struct Party {
  SafetyNumberFunction calculate_safety_number;
  HandshakeFunction perform_handshake;
};

}  // namespace autograph
