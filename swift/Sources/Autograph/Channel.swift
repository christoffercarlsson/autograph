import Clibautograph
import Foundation

private func countCertificates(_ certificates: [UInt8]) -> UInt32 {
  UInt32(certificates.count) / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
}

private func getSafetyNumber(_ a: [UInt8], _ b: [UInt8]) throws -> [UInt8] {
  try calculateSafetyNumber(a: a, b: b)
}

class DecryptionState {
  var decryptIndex: [UInt8]
  var messageIndex: [UInt8]
  var plaintextSize: [UInt8]
  var secretKey: [UInt8]
  var skippedKeys: [UInt8]

  init(secretKey: [UInt8]) {
    decryptIndex = createIndexBytes()
    messageIndex = createIndexBytes()
    plaintextSize = createSizeBytes()
    self.secretKey = secretKey
    skippedKeys = createSkippedKeysBytes()
  }

  func readMessageIndex() -> UInt64 {
    autograph_read_uint64(&messageIndex)
  }

  func readPlaintextSize() -> Int {
    Int(autograph_read_uint32(&plaintextSize))
  }

  func resizeData(_ plaintext: inout [UInt8]) -> [UInt8] {
    Array(plaintext[0 ..< readPlaintextSize()])
  }
}

class EncryptionState {
  var messageIndex: [UInt8]
  var secretKey: [UInt8]

  init(secretKey: [UInt8]) {
    messageIndex = createIndexBytes()
    self.secretKey = secretKey
  }

  func readMessageIndex() -> UInt64 {
    autograph_read_uint64(&messageIndex)
  }
}

public class Channel {
  var decryptState: DecryptionState?
  var encryptState: EncryptionState?
  var ourIdentityKey: [UInt8]
  var sign: SignFunction
  var theirPublicKey: [UInt8]?
  var transcript: [UInt8]?
  var verified: Bool

  init(sign: @escaping SignFunction, ourIdentityKey: [UInt8]) throws {
    if autograph_init() < 0 {
      throw AutographError.initialization
    }
    decryptState = nil
    encryptState = nil
    self.ourIdentityKey = ourIdentityKey
    self.sign = sign
    theirPublicKey = nil
    transcript = nil
    verified = false
  }

  public func calculateSafetyNumber() throws -> [UInt8] {
    if !isEstablished() {
      throw AutographError.channelUnestablished
    }
    return try getSafetyNumber(ourIdentityKey, theirPublicKey!)
  }

  public func close() throws {
    if !isEstablished() {
      throw AutographError.channelUnestablished
    }
    decryptState = nil
    encryptState = nil
    theirPublicKey = nil
    transcript = nil
    verified = false
  }

  public func decrypt(message: [UInt8]) throws -> (UInt64, [UInt8]) {
    if !isEstablished() {
      throw AutographError.channelUnestablished
    }
    var data = createPlaintextBytes(message.count)
    let success =
      autograph_decrypt(
        &data,
        &decryptState!.plaintextSize,
        &decryptState!.messageIndex,
        &decryptState!.decryptIndex,
        &decryptState!.skippedKeys,
        &decryptState!.secretKey,
        message,
        UInt32(message.count)
      ) == 0
    if !success {
      throw AutographError.decryption
    }
    data = decryptState!.resizeData(&data)
    return (
      decryptState!.readMessageIndex(),
      data
    )
  }

  public func encrypt(plaintext: [UInt8]) throws -> (UInt64, [UInt8]) {
    var ciphertext = createCiphertextBytes(plaintext.count)
    let success =
      autograph_encrypt(
        &ciphertext,
        &encryptState!.messageIndex,
        &encryptState!.secretKey,
        plaintext,
        UInt32(plaintext.count)
      ) == 0
    if !success {
      throw AutographError.encryption
    }
    return (encryptState!.readMessageIndex(), ciphertext)
  }

  public func isClosed() -> Bool {
    !(isEstablished() || isInitialized())
  }

  public func isEstablished() -> Bool {
    theirPublicKey != nil && decryptState != nil && encryptState != nil &&
      transcript == nil
      && verified
  }

  public func isInitialized() -> Bool {
    theirPublicKey != nil && decryptState != nil && encryptState != nil &&
      transcript != nil
      && !verified
  }

  public func performKeyExchange(
    isInitiator: Bool,
    ourEphemeralKeyPair: inout KeyPair,
    theirIdentityKey: [UInt8],
    theirEphemeralKey: [UInt8]
  ) throws -> [UInt8] {
    var handshake = createHandshakeBytes()
    var transcript = createTranscriptBytes()
    var ourSecretKey = createSecretKeyBytes()
    var theirSecretKey = createSecretKeyBytes()
    let transcriptSuccess =
      autograph_key_exchange_transcript(
        &transcript,
        isInitiator ? 1 : 0,
        ourIdentityKey,
        ourEphemeralKeyPair.publicKey,
        theirIdentityKey,
        theirEphemeralKey
      ) == 0
    if !transcriptSuccess {
      throw AutographError.keyExchange
    }
    let signature = try sign(transcript)
    let keyExchangeSuccess =
      autograph_key_exchange_signature(
        &handshake,
        &ourSecretKey,
        &theirSecretKey,
        isInitiator ? 1 : 0,
        signature,
        &ourEphemeralKeyPair.privateKey,
        theirEphemeralKey
      ) == 0
    if !keyExchangeSuccess {
      throw AutographError.keyExchange
    }
    decryptState = DecryptionState(secretKey: theirSecretKey)
    encryptState = EncryptionState(secretKey: ourSecretKey)
    theirPublicKey = theirIdentityKey
    self.transcript = transcript
    verified = false
    return handshake
  }

  public func signData(data: [UInt8]) throws -> [UInt8] {
    if !isEstablished() {
      throw AutographError.channelUnestablished
    }
    var subject = createSubjectBytes(data.count)
    autograph_subject(
      &subject,
      theirPublicKey,
      data,
      UInt32(data.count)
    )
    return try sign(subject)
  }

  public func signIdentity() throws -> [UInt8] {
    try sign(theirPublicKey!)
  }

  public func verifyData(certificates: [UInt8], data: [UInt8]) throws -> Bool {
    if !isEstablished() {
      throw AutographError.channelUnestablished
    }
    return autograph_verify_data(
      theirPublicKey,
      certificates,
      countCertificates(certificates),
      data,
      UInt32(data.count)
    ) == 0
  }

  public func verifyIdentity(certificates: [UInt8]) throws -> Bool {
    if !isEstablished() {
      throw AutographError.channelUnestablished
    }
    return autograph_verify_identity(
      theirPublicKey,
      certificates,
      countCertificates(certificates)
    ) == 0
  }

  public func verifyKeyExchange(theirHandshake: [UInt8]) throws {
    if isEstablished() {
      throw AutographError.channelAlreadyEstablished
    }
    if !isInitialized() {
      throw AutographError.channelUninitialized
    }
    verified =
      autograph_key_exchange_verify(
        transcript,
        theirPublicKey,
        decryptState!.secretKey,
        theirHandshake
      ) == 0
    transcript = nil
    if !verified {
      throw AutographError.keyExchangeVerification
    }
  }
}
