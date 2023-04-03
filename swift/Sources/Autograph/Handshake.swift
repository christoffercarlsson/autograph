import Clibautograph
import Foundation

internal func createHandshake(
  isInitiator: Bool,
  identityKeyPair: KeyPair,
  ephemeralKeyPair: KeyPair
) -> HandshakeFunction {
  let performHandshake: HandshakeFunction =
    { [ephemeralKeyPair] theirIdentityKey, theirEphemeralKey in
      var ourCiphertext = createHandshakeBytes()
      var transcript = createTranscriptBytes()
      var ourSecretKey = createSecretKeyBytes()
      var theirSecretKey = createSecretKeyBytes()
      try withUnsafeMutablePointer(
        to: &ephemeralKeyPair
          .privateKey
      ) { ephemeralPrivateKeyPointer in
        let result = autograph_handshake(
          getMutablePointer(&transcript),
          getMutablePointer(&ourCiphertext),
          getMutablePointer(&ourSecretKey),
          getMutablePointer(&theirSecretKey),
          isInitiator ? 1 : 0,
          getPointer(identityKeyPair.privateKey),
          getPointer(identityKeyPair.publicKey),
          ephemeralPrivateKeyPointer,
          getPointer(ephemeralKeyPair.publicKey),
          getPointer(theirIdentityKey),
          getPointer(theirEphemeralKey)
        )
        if result != 0 {
          throw AutographError.handshakeFailed
        }
      }
      return createSession(
        ourPrivateKey: identityKeyPair.privateKey,
        theirPublicKey: theirIdentityKey,
        transcript: transcript,
        ourSecretKey: ourSecretKey,
        theirSecretKey: theirSecretKey
      )
    }
  return performHandshake
}
