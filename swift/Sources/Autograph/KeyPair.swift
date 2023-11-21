import Clibautograph
import Foundation

public class KeyPair {
  public var privateKey: [UInt8]
  public var publicKey: [UInt8]

  init(privateKey: [UInt8], publicKey: [UInt8]) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }
}

public func generateEphemeralKeyPair() throws -> KeyPair {
  if autograph_init() < 0 {
    throw AutographError.initialization
  }
  let keyPair = KeyPair(
    privateKey: createPrivateKeyBytes(),
    publicKey: createPublicKeyBytes()
  )
  let success =
    autograph_key_pair_ephemeral(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 0
  if !success {
    throw AutographError.keyPairGeneration
  }
  return keyPair
}

public func generateIdentityKeyPair() throws -> KeyPair {
  if autograph_init() < 0 {
    throw AutographError.initialization
  }
  let keyPair = KeyPair(
    privateKey: createPrivateKeyBytes(),
    publicKey: createPublicKeyBytes()
  )
  let success =
    autograph_key_pair_identity(
      &keyPair.privateKey,
      &keyPair.publicKey
    ) == 0
  if !success {
    throw AutographError.keyPairGeneration
  }
  return keyPair
}
