import Clibautograph
import Foundation

internal func createDecrypt(state: DecryptionState) -> DecryptFunction {
  let decryptFunction: DecryptFunction = { [state] message in
    var data = createPlaintextBytes(size: message.count)
    let success = autograph_decrypt(
      &data,
      &state.messageIndex,
      &state.decryptIndex,
      &state.skippedKeys,
      &state.secretKey,
      message,
      UInt64(message.count)
    ) == 0
    return DecryptionResult(
      success: success,
      index: state.getMessageIndex(),
      data: data
    )
  }
  return decryptFunction
}

internal func createEncrypt(state: EncryptionState) -> EncryptFunction {
  let encryptFunction: EncryptFunction = { [state] data in
    var message = createMessageBytes(size: data.count)
    let success = autograph_encrypt(
      &message,
      &state.messageIndex,
      &state.secretKey,
      data,
      UInt64(data.count)
    ) == 0
    return EncryptionResult(
      success: success,
      index: state.getMessageIndex(),
      message: message
    )
  }
  return encryptFunction
}

internal func createSignData(
  sign: @escaping SignFunction,
  theirPublicKey: Bytes
) -> SignDataFunction {
  let signDataFunction: SignDataFunction = { [sign, theirPublicKey] data in
    var subject = createSubjectBytes(size: data.count)
    autograph_subject(
      &subject,
      theirPublicKey,
      data,
      UInt64(data.count)
    )
    return sign(subject)
  }
  return signDataFunction
}

internal func createSignIdentity(
  sign: @escaping SignFunction,
  theirPublicKey: Bytes
) -> SignIdentityFunction {
  let signIdentityFunction: SignIdentityFunction = { [sign, theirPublicKey] in
    sign(theirPublicKey)
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
