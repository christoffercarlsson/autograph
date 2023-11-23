#include "error.h"

namespace Autograph {

Error::Error(Type type) : std::runtime_error("Autograph error"), type(type) {}

const char* Error::what() const noexcept {
  switch (type) {
    case ChannelAlreadyEstablished:
      return "Channel already established";
    case ChannelAlreadyInitialized:
      return "Channel already initialized";
    case ChannelUnestablished:
      return "Channel unestablished";
    case ChannelUninitialized:
      return "Channel uninitialized";
    case Decryption:
      return "Decryption failed";
    case Encryption:
      return "Encryption failed";
    case Initialization:
      return "Initialization failed";
    case KeyExchange:
      return "Key exchange failed";
    case KeyExchangeVerification:
      return "Key exchange verification failed";
    case KeyPairGeneration:
      return "Key pair generation failed";
    case SafetyNumberCalculation:
      return "Safety number calculation failed";
    case Signing:
      return "Signing failed";
    default:
      return std::runtime_error::what();
  }
}

}  // namespace Autograph
