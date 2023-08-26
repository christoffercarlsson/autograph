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

public class SignResult {
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

public typealias DecryptFunction = (Bytes) -> DecryptionResult
public typealias EncryptFunction = (Bytes) -> EncryptionResult
public typealias SignDataFunction = (Bytes) -> SignResult
public typealias SignIdentityFunction = () -> SignResult
public typealias VerifyDataFunction = (Bytes, Bytes) -> Bool
public typealias VerifyIdentityFunction = (Bytes) -> Bool

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
  var encrypt: EncryptFunction
  var decrypt: DecryptFunction
  var signData: SignDataFunction
  var signIdentity: SignIdentityFunction
  var verifyData: VerifyDataFunction
  var verifyIdentity: VerifyIdentityFunction

  init(
    decrypt: @escaping DecryptFunction,
    encrypt: @escaping EncryptFunction,
    signData: @escaping SignDataFunction,
    signIdentity: @escaping SignIdentityFunction,
    verifyData: @escaping VerifyDataFunction,
    verifyIdentity: @escaping VerifyIdentityFunction
  ) {
    self.decrypt = decrypt
    self.encrypt = encrypt
    self.signData = signData
    self.signIdentity = signIdentity
    self.verifyData = verifyData
    self.verifyIdentity = verifyIdentity
  }
}

public class KeyExchangeVerificationResult {
  var success: Bool
  var session: Session

  init(success: Bool, session: Session) {
    self.success = success
    self.session = session
  }
}

public typealias KeyExchangeVerificationFunction = (Bytes)
  -> KeyExchangeVerificationResult

public class KeyExchange {
  var handshake: Bytes
  var verify: KeyExchangeVerificationFunction

  init(handshake: Bytes, verify: @escaping KeyExchangeVerificationFunction) {
    self.handshake = handshake
    self.verify = verify
  }
}

public class KeyExchangeResult {
  var success: Bool
  var keyExchange: KeyExchange

  init(success: Bool, keyExchange: KeyExchange) {
    self.success = success
    self.keyExchange = keyExchange
  }
}

public typealias KeyExchangeFunction = (inout KeyPair, Bytes, Bytes)
  -> KeyExchangeResult

public typealias SignFunction = (Bytes) -> SignResult

public class Party {
  var calculateSafetyNumber: SafetyNumberFunction
  var performKeyExchange: KeyExchangeFunction

  init(
    calculateSafetyNumber: @escaping SafetyNumberFunction,
    performKeyExchange: @escaping KeyExchangeFunction
  ) {
    self.calculateSafetyNumber = calculateSafetyNumber
    self.performKeyExchange = performKeyExchange
  }
}
