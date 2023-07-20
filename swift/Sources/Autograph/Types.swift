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

public class KeyPairResult {
  var success: Bool
  var keyPair: KeyPair

  init(success: Bool, keyPair: KeyPair) {
    self.success = success
    self.keyPair = keyPair
  }
}

public class CertificationResult {
  var success: Bool
  var signature: Bytes

  init(success: Bool, signature: Bytes) {
    self.success = success
    self.signature = signature
  }
}

public class DecryptionResult {
  var success: Bool
  var data: Bytes

  init(success: Bool, data: Bytes) {
    self.success = success
    self.data = data
  }
}

public class EncryptionResult {
  var success: Bool
  var message: Bytes

  init(success: Bool, message: Bytes) {
    self.success = success
    self.message = message
  }
}

public typealias CertifyFunction = (Bytes?) -> CertificationResult
public typealias DecryptFunction = (Bytes) -> DecryptionResult
public typealias EncryptFunction = (Bytes) -> EncryptionResult
public typealias VerifyFunction = (Bytes, Bytes?) -> Bool

public class SafetyNumberResult {
  var success: Bool
  var safetyNumber: Bytes

  init(success: Bool, safetyNumber: Bytes) {
    self.success = success
    self.safetyNumber = safetyNumber
  }
}

public typealias SafetyNumberFunction = (Bytes) -> SafetyNumberResult

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

public class SessionResult {
  var success: Bool
  var session: Session

  init(success: Bool, session: Session) {
    self.success = success
    self.session = session
  }
}

public typealias SessionFunction = (Bytes) -> SessionResult

public class Handshake {
  var message: Bytes
  var establishSession: SessionFunction

  init(message: Bytes, establishSession: @escaping SessionFunction) {
    self.message = message
    self.establishSession = establishSession
  }
}

public class HandshakeResult {
  var success: Bool
  var handshake: Handshake

  init(success: Bool, handshake: Handshake) {
    self.success = success
    self.handshake = handshake
  }
}

public typealias HandshakeFunction = (Bytes, Bytes) -> HandshakeResult

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
