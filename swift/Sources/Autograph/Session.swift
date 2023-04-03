import Clibautograph
import Foundation

private func createCertify(
  ourPrivateKey: Bytes,
  theirPublicKey: Bytes,
  theirSecretKey: Bytes
) -> CertifyFunction {
  let certifyFunction: CertifyFunction = { message in
    var signature = createSignatureBytes()
    let result = autograph_certify(
      getMutablePointer(&signature),
      getPointer(ourPrivateKey),
      getPointer(theirPublicKey),
      getPointer(theirSecretKey),
      getPointer(message),
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
  let decryptFunction: DecryptFunction = { message in
    var plaintext = createPlaintextBytes(size: message.count)
    let result = autograph_decrypt(
      getMutablePointer(&plaintext),
      getPointer(theirSecretKey),
      getPointer(message),
      UInt64(message.count)
    )
    if result != 0 {
      throw AutographError.decryptionFailed
    }
    return plaintext
  }
  return decryptFunction
}

private func createEncrypt(ourSecretKey: Bytes) -> EncryptFunction {
  let encryptFunction: EncryptFunction = { plaintext in
    var message = createMessageBytes(size: plaintext.count)
    let result = autograph_encrypt(
      getMutablePointer(&message),
      getPointer(ourSecretKey),
      getPointer(plaintext),
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
  let verifyFunction: VerifyFunction = { certificates, message in
    let certificateCount = certificates
      .count /
      (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
    let result = autograph_verify(
      getPointer(theirPublicKey),
      getPointer(theirSecretKey),
      getPointer(certificates),
      UInt64(certificateCount),
      getPointer(message),
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
  let sessionFunction: SessionFunction = { theirCiphertext in
    let result = autograph_session(
      getPointer(transcript),
      getPointer(theirPublicKey),
      getPointer(theirSecretKey),
      getPointer(theirCiphertext)
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
