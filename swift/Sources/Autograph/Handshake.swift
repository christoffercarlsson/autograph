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
    let success = autograph_handshake(
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
    ) == 0
    let establishSession: SessionFunction = createSession(
      ourPrivateKey: identityKeyPair.privateKey,
      theirPublicKey: theirIdentityKey,
      transcript: transcript,
      ourSecretKey: ourSecretKey,
      theirSecretKey: theirSecretKey
    )
    let handshake = Handshake(
      message: ourCiphertext,
      establishSession: establishSession
    )
    return HandshakeResult(success: success, handshake: handshake)
  }
  return performHandshake
}
