#pragma once

#include <functional>
#include <vector>

namespace autograph {

using Chunk = std::vector<unsigned char>;

using KeyPair = struct KeyPair {
  Chunk public_key;
  Chunk private_key;
};

using Certificate = struct Certificate {
  Chunk identity_key;
  Chunk signature;
};

using CertificateList = std::vector<Certificate>;

using CertifyFunction = std::function<Chunk(const Chunk&)>;

using DecryptFunction = std::function<Chunk(const Chunk&)>;

using EncryptFunction = std::function<Chunk(const Chunk&)>;

using SafetyNumberFunction = std::function<Chunk(const Chunk&)>;

using VerifyFunction =
    std::function<bool(const CertificateList&, const Chunk&)>;

using Session = struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

using SessionFunction = std::function<Session(const Chunk&)>;

using Handshake = struct Handshake {
  Chunk ciphertext;
  SessionFunction verify_session;
};

using HandshakeFunction = std::function<Handshake(const Chunk&, const Chunk&)>;

using Party = struct Party {
  SafetyNumberFunction calculate_safety_number;
  Chunk ephemeral_key;
  HandshakeFunction perform_handshake;
  Chunk identity_key;
};

}  // namespace autograph
