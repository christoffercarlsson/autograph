#pragma once

#include <functional>
#include <vector>

using Byte = unsigned char;

using Chunk = std::vector<Byte>;

using KeyPair = struct {
  Chunk public_key;
  Chunk private_key;
};

using DecryptFunction = std::function<Chunk(const Chunk&)>;

using DeriveKeyFunction = std::function<Chunk()>;

using EncryptFunction = std::function<Chunk(const Chunk&)>;

using Session = struct {
  DecryptFunction decrypt;
  DeriveKeyFunction derive_key;
  EncryptFunction encrypt;
};

using SessionFunction = std::function<Session(const Chunk&)>;

using Handshake = struct {
  Chunk ciphertext;
  SessionFunction session;
};

using HandshakeFunction = std::function<Handshake(const Chunk&, const Chunk&)>;
