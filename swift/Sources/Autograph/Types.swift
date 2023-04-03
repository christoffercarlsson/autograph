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

public typealias CertifyFunction = (Bytes?) throws -> Bytes
public typealias DecryptFunction = (Bytes) throws -> Bytes
public typealias EncryptFunction = (Bytes) throws -> Bytes
public typealias VerifyFunction = (Bytes, Bytes?) -> Bool

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

public typealias HandshakeFunction = (Bytes, Bytes) throws -> SessionFunction

public class Party {
  var calculateSafetyNumber: SafetyNumberFunction
  var ephemeralKey: Bytes
  var identityKey: Bytes
  var performHandshake: HandshakeFunction

  init(
    calculateSafetyNumber: @escaping SafetyNumberFunction,
    ephemeralKey: Bytes,
    identityKey: Bytes,
    performHandshake: @escaping HandshakeFunction
  ) {
    self.calculateSafetyNumber = calculateSafetyNumber
    self.ephemeralKey = ephemeralKey
    self.identityKey = identityKey
    self.performHandshake = performHandshake
  }
}
