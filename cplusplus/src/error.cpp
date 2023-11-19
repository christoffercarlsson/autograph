#include "error.h"

namespace Autograph {

Error::Error(Type type) : std::runtime_error("Autograph error"), type(type) {}

const char* Error::what() const noexcept {
  switch (type) {
    case ChannelAlreadyEstablishedError:
      return "Channel already established";
    case ChannelAlreadyInitializedError:
      return "Channel already initialized";
    case ChannelUnestablishedError:
      return "Channel unestablished";
    case ChannelUninitializedError:
      return "Channel uninitialized";
    case DecryptionError:
      return "Decryption failed";
    case EncryptionError:
      return "Encryption failed";
    case InitializationError:
      return "Initialization failed";
    case KeyExchangeError:
      return "Key exchange failed";
    case KeyExchangeVerificationError:
      return "Key exchange verification failed";
    case KeyPairGenerationError:
      return "Key pair generation failed";
    case SafetyNumberCalculationError:
      return "Safety number calculation failed";
    case SigningError:
      return "Signing failed";
    default:
      return std::runtime_error::what();
  }
}

}  // namespace Autograph
