import Clibautograph
import Foundation

internal func createHandshake(
  isInitiator: Bool,
  identityKeyPair: KeyPair,
  ephemeralKeyPair: KeyPair
) -> HandshakeFunction {
  let performHandshake: HandshakeFunction = { [
    isInitiator,
    identityKeyPair,
    ephemeralKeyPair
  ] theirIdentityKey, theirEphemeralKey in
    var ourCiphertext = createHandshakeBytes()
    var transcript = createTranscriptBytes()
    var ourSecretKey = createSecretKeyBytes()
    var theirSecretKey = createSecretKeyBytes()
    let result = autograph_handshake(
      &transcript,
      &ourCiphertext,
      &ourSecretKey,
      &theirSecretKey,
      isInitiator ? 1 : 0,
      identityKeyPair.privateKey,
      identityKeyPair.publicKey,
      &ephemeralKeyPair.privateKey,
      ephemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    if result != 0 {
      throw AutographError.handshakeFailed
    }
    let establishSession: SessionFunction = createSession(
      ourPrivateKey: identityKeyPair.privateKey,
      theirPublicKey: theirIdentityKey,
      transcript: transcript,
      ourSecretKey: ourSecretKey,
      theirSecretKey: theirSecretKey
    )
    return Handshake(
      message: ourCiphertext,
      establishSession: establishSession
    )
  }
  return performHandshake
}
