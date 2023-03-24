#pragma once

#include <functional>
#include <vector>

using Byte = unsigned char;

using Chunk = std::vector<Byte>;

using KeyPair = struct KeyPair {
  Chunk public_key;
  Chunk private_key;
};

using Certificate = struct Certificate {
  Chunk identity_key;
  Chunk signature;
};

using CertificateList = std::vector<Certificate>;

using CalculateSafetyNumberFunction = std::function<Chunk(const Chunk&)>;

using CertifyFunction = std::function<Chunk(const Chunk&)>;

using DecryptFunction = std::function<Chunk(const Chunk&)>;

using EncryptFunction = std::function<Chunk(const Chunk&)>;

using VerifyFunction =
    std::function<bool(const CertificateList&, const Chunk&)>;

using Session = struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

using SessionFunction = std::function<Session(const Chunk&)>;

using SecretKeys = struct SecretKeys {
  Chunk our_secret_key;
  Chunk their_secret_key;
};

using Handshake = struct Handshake {
  Chunk ciphertext;
  SessionFunction session;
};

using HandshakeFunction = std::function<Handshake(const Chunk&, const Chunk&)>;

using Party = struct Party {
  CalculateSafetyNumberFunction calculate_safety_number;
  Chunk ephemeral_key;
  HandshakeFunction handshake;
  Chunk identity_key;
};
