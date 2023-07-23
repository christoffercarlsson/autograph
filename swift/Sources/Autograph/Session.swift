import Clibautograph
import Foundation

private func createCertify(
  sign: @escaping SignFunction,
  theirPublicKey: Bytes
) -> CertifyFunction {
  let certifyFunction: CertifyFunction = { [sign, theirPublicKey] data in
    let dataSize = UInt64((data != nil) ? data!.count : 0)
    var subject = createSubjectBytes(size: dataSize)
    autograph_subject(
      &subject,
      theirPublicKey,
      data,
      dataSize
    )
    let result = sign(subject)
    return CertificationResult(
      success: result.success,
      signature: result.signature
    )
  }
  return certifyFunction
}

private func createDecrypt(theirSecretKey: Bytes) -> DecryptFunction {
  let decryptFunction: DecryptFunction = { [theirSecretKey] message in
    var data = createPlaintextBytes(size: message.count)
    let success = autograph_decrypt(
      &data,
      theirSecretKey,
      message,
      UInt64(message.count)
    ) == 0
    return DecryptionResult(success: success, data: data)
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
  let encryptFunction: EncryptFunction = { [ourSecretKey, indexCounter] data in
    indexCounter.increment()
    var message = createMessageBytes(size: data.count)
    let success = autograph_encrypt(
      &message,
      ourSecretKey,
      indexCounter.index,
      data,
      UInt64(data.count)
    ) == 0
    return EncryptionResult(success: success, message: message)
  }
  return encryptFunction
}

private func createVerify(
  theirPublicKey: Bytes
) -> VerifyFunction {
  let verifyFunction: VerifyFunction = { [theirPublicKey] certificates, data in
    let certificateCount = certificates
      .count /
      (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
    let result = autograph_verify(
      theirPublicKey,
      certificates,
      UInt64(certificateCount),
      data,
      UInt64((data != nil) ? data!.count : 0)
    )
    return result == 0
  }
  return verifyFunction
}

internal func createSession(
  sign: @escaping SignFunction,
  theirPublicKey: Bytes,
  transcript: Bytes,
  ourSecretKey: Bytes,
  theirSecretKey: Bytes
) -> SessionFunction {
  let sessionFunction: SessionFunction = { [
    sign,
    theirPublicKey,
    transcript,
    ourSecretKey,
    theirSecretKey
  ] theirCiphertext in
    let success = autograph_session(
      transcript,
      theirPublicKey,
      theirSecretKey,
      theirCiphertext
    ) == 0
    let session = Session(
      certify: createCertify(
        sign: sign,
        theirPublicKey: theirPublicKey
      ),
      decrypt: createDecrypt(theirSecretKey: theirSecretKey),
      encrypt: createEncrypt(ourSecretKey: ourSecretKey),
      verify: createVerify(
        theirPublicKey: theirPublicKey
      )
    )
    return SessionResult(success: success, session: session)
  }
  return sessionFunction
}
