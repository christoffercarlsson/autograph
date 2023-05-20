import Clibautograph
import Foundation

private func createCertify(
  ourPrivateKey: Bytes,
  theirPublicKey: Bytes,
  theirSecretKey: Bytes
) -> CertifyFunction {
  let certifyFunction: CertifyFunction =
    { [ourPrivateKey, theirPublicKey, theirSecretKey] message in
      var signature = createSignatureBytes()
      let result = autograph_certify(
        &signature,
        ourPrivateKey,
        theirPublicKey,
        theirSecretKey,
        message,
        UInt64((message != nil) ? message!.count : 0)
      )
      if result != 0 {
        throw AutographError.certificationFailed
      }
      return signature
    }
  return certifyFunction
}

private func createDecrypt(theirSecretKey: Bytes) -> DecryptFunction {
  let decryptFunction: DecryptFunction = { [theirSecretKey] message in
    var plaintext = createPlaintextBytes(size: message.count)
    let result = autograph_decrypt(
      &plaintext,
      theirSecretKey,
      message,
      UInt64(message.count)
    )
    if result != 0 {
      throw AutographError.decryptionFailed
    }
    return plaintext
  }
  return decryptFunction
}

private class EncryptIndexCounter {
  var index: UInt32

  init() {
    index = 0
  }

  public func increment() {
    index += 1
  }
}

private func createEncrypt(ourSecretKey: Bytes) -> EncryptFunction {
  let indexCounter = EncryptIndexCounter()
  let encryptFunction: EncryptFunction =
    { [ourSecretKey, indexCounter] plaintext in
      indexCounter.increment()
      var message = createMessageBytes(size: plaintext.count)
      let result = autograph_encrypt(
        &message,
        ourSecretKey,
        indexCounter.index,
        plaintext,
        UInt64(plaintext.count)
      )
      if result != 0 {
        throw AutographError.encryptionFailed
      }
      return message
    }
  return encryptFunction
}

private func createVerify(
  theirPublicKey: Bytes,
  theirSecretKey: Bytes
) -> VerifyFunction {
  let verifyFunction: VerifyFunction =
    { [theirPublicKey, theirSecretKey] certificates, message in
      let certificateCount = certificates
        .count /
        (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
      let result = autograph_verify(
        theirPublicKey,
        theirSecretKey,
        certificates,
        UInt64(certificateCount),
        message,
        UInt64((message != nil) ? message!.count : 0)
      )
      return result == 0
    }
  return verifyFunction
}

internal func createSession(
  ourPrivateKey: Bytes,
  theirPublicKey: Bytes,
  transcript: Bytes,
  ourSecretKey: Bytes,
  theirSecretKey: Bytes
) -> SessionFunction {
  let sessionFunction: SessionFunction = { [
    ourPrivateKey,
    theirPublicKey,
    transcript,
    ourSecretKey,
    theirSecretKey
  ] theirCiphertext in
    let result = autograph_session(
      transcript,
      theirPublicKey,
      theirSecretKey,
      theirCiphertext
    )
    if result != 0 {
      throw AutographError.sessionFailed
    }
    return Session(
      certify: createCertify(
        ourPrivateKey: ourPrivateKey,
        theirPublicKey: theirPublicKey,
        theirSecretKey: theirSecretKey
      ),
      decrypt: createDecrypt(theirSecretKey: theirSecretKey),
      encrypt: createEncrypt(ourSecretKey: ourSecretKey),
      verify: createVerify(
        theirPublicKey: theirPublicKey,
        theirSecretKey: theirSecretKey
      )
    )
  }
  return sessionFunction
}
