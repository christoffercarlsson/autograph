import Clibautograph
import Foundation

public struct Autograph {
  public init() {
    autograph_init()
  }

  public func createInitiator(
    sign: @escaping SignFunction,
    identityPublicKey: Bytes
  ) -> Party {
    createParty(
      isInitiator: true,
      sign: sign,
      identityPublicKey: identityPublicKey
    )
  }

  public func createInitiator(
    identityKeyPair: KeyPair
  ) -> Party {
    createInitiator(
      sign: createSign(identityPrivateKey: identityKeyPair.privateKey),
      identityPublicKey: identityKeyPair.publicKey
    )
  }

  public func createResponder(
    sign: @escaping SignFunction,
    identityPublicKey: Bytes
  ) -> Party {
    createParty(
      isInitiator: false,
      sign: sign,
      identityPublicKey: identityPublicKey
    )
  }

  public func createResponder(
    identityKeyPair: KeyPair
  ) -> Party {
    createResponder(
      sign: createSign(identityPrivateKey: identityKeyPair.privateKey),
      identityPublicKey: identityKeyPair.publicKey
    )
  }

  public func createSign(identityPrivateKey: Bytes) -> SignFunction {
    let sign: SignFunction = { [identityPrivateKey] subject in
      var signature = createSignatureBytes()
      let success = autograph_sign_subject(
        &signature,
        identityPrivateKey,
        subject,
        UInt64(subject.count)
      ) == 0
      return SignResult(success: success, signature: signature)
    }
    return sign
  }

  public func generateEphemeralKeyPair() -> KeyPairResult {
    let keyPair = KeyPair(
      privateKey: createPrivateKeyBytes(),
      publicKey: createPublicKeyBytes()
    )
    let success = autograph_key_pair_ephemeral(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 0
    return KeyPairResult(success: success, keyPair: keyPair)
  }

  public func generateIdentityKeyPair() -> KeyPairResult {
    let keyPair = KeyPair(
      privateKey: createPrivateKeyBytes(),
      publicKey: createPublicKeyBytes()
    )
    let success = autograph_key_pair_identity(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 0
    return KeyPairResult(success: success, keyPair: keyPair)
  }
}
