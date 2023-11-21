#ifndef AUTOGRAPH_ERROR_H
#define AUTOGRAPH_ERROR_H

#ifdef __cplusplus
#include <stdexcept>
#include <string>

namespace Autograph {

class Error : public std::runtime_error {
 public:
  enum Type {
    ChannelAlreadyEstablishedError,
    ChannelAlreadyInitializedError,
    ChannelUnestablishedError,
    ChannelUninitializedError,
    DecryptionError,
    EncryptionError,
    InitializationError,
    KeyExchangeError,
    KeyExchangeVerificationError,
    KeyPairGenerationError,
    SafetyNumberCalculationError,
    SigningError
  };

  Type type;

  Error(Type type);

  const char* what() const noexcept override;
};

}  // namespace Autograph
#endif

#endif
