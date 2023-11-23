#ifndef AUTOGRAPH_ERROR_H
#define AUTOGRAPH_ERROR_H

#ifdef __cplusplus
#include <stdexcept>
#include <string>

namespace Autograph {

class Error : public std::runtime_error {
 public:
  enum Type {
    ChannelAlreadyEstablished,
    ChannelAlreadyInitialized,
    ChannelUnestablished,
    ChannelUninitialized,
    Decryption,
    Encryption,
    Initialization,
    KeyExchange,
    KeyExchangeVerification,
    KeyPairGeneration,
    SafetyNumberCalculation,
    Signing
  };

  Type type;

  Error(Type type);

  const char* what() const noexcept override;
};

}  // namespace Autograph
#endif

#endif
