import Foundation

public enum AutographError: Error {
  case channelAlreadyEstablished
  case channelAlreadyInitialized
  case channelUnestablished
  case channelUninitialized
  case decryption
  case encryption
  case initialization
  case keyExchange
  case keyExchangeVerification
  case keyPairGeneration
  case safetyNumberCalculation
  case signing
}
