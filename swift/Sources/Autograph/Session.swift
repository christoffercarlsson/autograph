import Clibautograph
import Foundation

internal func createDecrypt(state: DecryptionState) -> DecryptFunction {
  let decryptFunction: DecryptFunction = { [state] message in
    var data = createPlaintextBytes(message.count)
    let success = autograph_decrypt(
      &data,
      &state.plaintextSize,
      &state.messageIndex,
      &state.decryptIndex,
      &state.skippedKeys,
      &state.secretKey,
      message,
      UInt32(message.count)
    ) == 0
    return DecryptionResult(
      success: success,
      index: state.readMessageIndex(),
      data: state.resizeData(&data)
    )
  }
  return decryptFunction
}

internal func createEncrypt(state: EncryptionState) -> EncryptFunction {
  let encryptFunction: EncryptFunction = { [state] plaintext in
    var message = createMessageBytes(plaintext.count)
    let success = autograph_encrypt(
      &message,
      &state.messageIndex,
      &state.secretKey,
      plaintext,
      UInt32(plaintext.count)
    ) == 0
    return EncryptionResult(
      success: success,
      index: state.readMessageIndex(),
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
    var subject = createSubjectBytes(data.count)
    autograph_subject(
      &subject,
      theirPublicKey,
      data,
      UInt32(data.count)
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

private func countCertificates(_ certificates: Bytes) -> UInt32 {
  UInt32(certificates.count / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE))
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
        UInt32(data.count)
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
