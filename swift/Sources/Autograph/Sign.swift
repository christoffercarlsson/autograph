import Clibautograph
import Foundation

public typealias SignFunction = ([UInt8]) throws -> [UInt8]

public func createSign(identityPrivateKey: [UInt8]) -> SignFunction {
  let sign: SignFunction = { [identityPrivateKey] subject in
    var signature = createSignatureBytes()
    let success =
      autograph_sign_subject(
        &signature,
        identityPrivateKey,
        subject,
        UInt32(subject.count)
      ) == 0
    if !success {
      throw AutographError.signing
    }
    return signature
  }
  return sign
}
