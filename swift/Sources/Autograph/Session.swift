import Clibautograph
import Foundation

internal func createDecrypt(theirSecretKey: Bytes) -> DecryptFunction {
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

internal class EncryptionIndexCounter {
  var index: UInt64

  init() {
    index = 0
  }

  public func increment() {
    index += 1
  }
}

internal func createEncrypt(ourSecretKey: Bytes) -> EncryptFunction {
  let indexCounter = EncryptionIndexCounter()
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

internal func createSignData(
  sign: @escaping SignFunction,
  theirPublicKey: Bytes
) -> SignDataFunction {
  let signDataFunction: SignDataFunction = { [sign, theirPublicKey] data in
    let dataSize = UInt64(data.count)
    var subject = createSubjectBytes(size: dataSize)
    autograph_subject(
      &subject,
      theirPublicKey,
      data,
      dataSize
    )
    let result = sign(subject)
    return SignResult(
      success: result.success,
      signature: result.signature
    )
  }
  return signDataFunction
}

internal func createSignIdentity(
  sign: @escaping SignFunction,
  theirPublicKey: Bytes
) -> SignIdentityFunction {
  let signIdentityFunction: SignIdentityFunction = { [sign, theirPublicKey] in
    let result = sign(theirPublicKey)
    return SignResult(
      success: result.success,
      signature: result.signature
    )
  }
  return signIdentityFunction
}

private func countCertificates(_ certificates: Bytes) -> UInt64 {
  UInt64(certificates.count / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE))
}

internal func createVerifyData(
  theirPublicKey: Bytes
) -> VerifyDataFunction {
  let verifyDataFunction: VerifyDataFunction =
    { [theirPublicKey] certificates, data in
      autograph_verify_data(
        theirPublicKey,
        certificates,
        countCertificates(certificates),
        data,
        UInt64(data.count)
      ) == 0
    }
  return verifyDataFunction
}

internal func createVerifyIdentity(
  theirPublicKey: Bytes
) -> VerifyIdentityFunction {
  let verifyIdentityFunction: VerifyIdentityFunction =
    { [theirPublicKey] certificates in
      autograph_verify_identity(
        theirPublicKey,
        certificates,
        countCertificates(certificates)
      ) == 0
    }
  return verifyIdentityFunction
}
