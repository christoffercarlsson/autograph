#pragma once

#include <functional>
#include <vector>

namespace autograph {

using ByteVector = std::vector<unsigned char>;

struct KeyPair {
  ByteVector private_key;
  ByteVector public_key;
};

using CertifyFunction = std::function<ByteVector(const ByteVector &)>;

using DecryptFunction = std::function<ByteVector(const ByteVector &)>;

using EncryptFunction = std::function<ByteVector(const ByteVector &)>;

using SafetyNumberFunction = std::function<ByteVector(const ByteVector &)>;

using VerifyFunction =
    std::function<bool(const ByteVector &, const ByteVector &)>;

struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

using SessionFunction = std::function<Session(const ByteVector &)>;

struct Handshake {
  ByteVector handshake;
  SessionFunction establish_session;
};

using HandshakeFunction =
    std::function<Handshake(const ByteVector &, const ByteVector &)>;

struct Party {
  SafetyNumberFunction calculate_safety_number;
  HandshakeFunction perform_handshake;
};

}  // namespace autograph
