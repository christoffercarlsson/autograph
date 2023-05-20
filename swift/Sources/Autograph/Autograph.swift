import Clibautograph
import Foundation

public struct Autograph {
  public init() throws {
    if autograph_init() != 0 {
      throw AutographError.initializationFailed
    }
  }

  public func createInitiator(
    identityKeyPair: KeyPair,
    ephemeralKeyPair: KeyPair
  ) -> Party {
    createParty(
      isInitiator: true,
      identityKeyPair: identityKeyPair,
      ephemeralKeyPair: ephemeralKeyPair
    )
  }

  public func createResponder(
    identityKeyPair: KeyPair,
    ephemeralKeyPair: KeyPair
  ) -> Party {
    createParty(
      isInitiator: false,
      identityKeyPair: identityKeyPair,
      ephemeralKeyPair: ephemeralKeyPair
    )
  }

  public func generateEphemeralKeyPair() throws -> KeyPair {
    let keyPair = KeyPair(
      privateKey: createPrivateKeyBytes(),
      publicKey: createPublicKeyBytes()
    )
    let result = autograph_key_pair_ephemeral(
      &keyPair.privateKey,
      &keyPair.publicKey
    )
    if result != 0 {
      throw AutographError.keyGenerationFailed
    }
    return keyPair
  }

  public func generateIdentityKeyPair() throws -> KeyPair {
    let keyPair = KeyPair(
      privateKey: createPrivateKeyBytes(),
      publicKey: createPublicKeyBytes()
    )
    let result = autograph_key_pair_identity(
      &keyPair.privateKey,
      &keyPair.publicKey
    )
    if result != 0 {
      throw AutographError.keyGenerationFailed
    }
    return keyPair
  }
}
