#pragma once

#include <functional>
#include <vector>

namespace autograph {

using Bytes = std::vector<unsigned char>;

struct KeyPair {
  Bytes private_key;
  Bytes public_key;
};

using CertifyFunction = std::function<Bytes(const Bytes &)>;

using DecryptFunction = std::function<Bytes(const Bytes &)>;

using EncryptFunction = std::function<Bytes(const Bytes &)>;

using SafetyNumberFunction = std::function<Bytes(const Bytes &)>;

using VerifyFunction = std::function<bool(const Bytes &, const Bytes &)>;

struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

using SessionFunction = std::function<Session(const Bytes &)>;

struct Handshake {
  Bytes message;
  SessionFunction establish_session;
};

using HandshakeFunction =
    std::function<Handshake(const Bytes &, const Bytes &)>;

struct Party {
  SafetyNumberFunction calculate_safety_number;
  HandshakeFunction perform_handshake;
};

}  // namespace autograph
