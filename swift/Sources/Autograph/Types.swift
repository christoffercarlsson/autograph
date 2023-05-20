import Foundation

public typealias Bytes = [UInt8]

public class KeyPair {
  var privateKey: Bytes
  var publicKey: Bytes

  init(privateKey: Bytes, publicKey: Bytes) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }
}

public enum AutographError: Error {
  case certificationFailed
  case decryptionFailed
  case encryptionFailed
  case handshakeFailed
  case initializationFailed
  case keyGenerationFailed
  case safetyNumberFailed
  case sessionFailed
}

public typealias CertifyFunction = (Bytes?) throws -> Bytes
public typealias DecryptFunction = (Bytes) throws -> Bytes
public typealias EncryptFunction = (Bytes) throws -> Bytes
public typealias VerifyFunction = (Bytes, Bytes?) -> Bool

public class Session {
  var certify: CertifyFunction
  var decrypt: DecryptFunction
  var encrypt: EncryptFunction
  var verify: VerifyFunction

  init(
    certify: @escaping CertifyFunction,
    decrypt: @escaping DecryptFunction,
    encrypt: @escaping EncryptFunction,
    verify: @escaping VerifyFunction
  ) {
    self.certify = certify
    self.decrypt = decrypt
    self.encrypt = encrypt
    self.verify = verify
  }
}

public typealias SafetyNumberFunction = (Bytes) throws -> Bytes

public typealias SessionFunction = (Bytes) throws -> Session

public class Handshake {
  var message: Bytes
  var establishSession: SessionFunction

  init(message: Bytes, establishSession: @escaping SessionFunction) {
    self.message = message
    self.establishSession = establishSession
  }
}

public typealias HandshakeFunction = (Bytes, Bytes) throws -> Handshake

public class Party {
  var calculateSafetyNumber: SafetyNumberFunction
  var performHandshake: HandshakeFunction

  init(
    calculateSafetyNumber: @escaping SafetyNumberFunction,
    performHandshake: @escaping HandshakeFunction
  ) {
    self.calculateSafetyNumber = calculateSafetyNumber
    self.performHandshake = performHandshake
  }
}
