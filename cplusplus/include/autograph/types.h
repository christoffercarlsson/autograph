#pragma once

#include <functional>

#include "autograph/core/handshake.h"
#include "autograph/core/key_pair.h"
#include "autograph/core/safety_number.h"
#include "autograph/crypto/kdf.h"
#include "autograph/crypto/sign.h"

namespace autograph {

using Handshake = unsigned char[autograph_core_handshake_SIZE];

using PrivateKey = unsigned char[autograph_core_key_pair_PRIVATE_KEY_SIZE];

using PublicKey = unsigned char[autograph_core_key_pair_PUBLIC_KEY_SIZE];

using SafetyNumber = unsigned char[autograph_core_safety_number_SIZE];

using Signature = unsigned char[autograph_crypto_sign_SIGNATURE_SIZE];

using CertifyFunction = std::function<void(unsigned char*, const unsigned char*,
                                           const unsigned long long)>;

using DecryptFunction = std::function<void(unsigned char*, const unsigned char*,
                                           const unsigned long long)>;

using EncryptFunction = std::function<void(unsigned char*, const unsigned char*,
                                           const unsigned long long)>;

using SafetyNumberFunction =
    std::function<void(unsigned char*, const unsigned char*)>;

using VerifyFunction =
    std::function<bool(const unsigned char*, const unsigned long long,
                       const unsigned char*, const unsigned long long)>;

struct Session {
  CertifyFunction certify;
  DecryptFunction decrypt;
  EncryptFunction encrypt;
  VerifyFunction verify;
};

using SessionFunction = std::function<Session(const unsigned char*)>;

using HandshakeFunction = std::function<SessionFunction(
    unsigned char*, const unsigned char*, const unsigned char*)>;

struct Party {
  SafetyNumberFunction calculate_safety_number;
  HandshakeFunction perform_handshake;
};

}  // namespace autograph
