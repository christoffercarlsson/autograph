import Clibautograph
import Foundation

internal func createHandshake(
  isInitiator: Bool,
  sign: @escaping SignFunction,
  identityPublicKey: Bytes
) -> HandshakeFunction {
  let performHandshake: HandshakeFunction = { [
    isInitiator,
    sign,
    identityPublicKey
  ] ephemeralKeyPair, theirIdentityKey, theirEphemeralKey in
    let safeSign = createSafeSign(sign: sign)
    var ourCiphertext = createHandshakeBytes()
    var transcript = createTranscriptBytes()
    var ourSecretKey = createSecretKeyBytes()
    var theirSecretKey = createSecretKeyBytes()
    let transcriptSuccess = autograph_transcript(
      &transcript,
      isInitiator ? 1 : 0,
      identityPublicKey,
      ephemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    ) == 0
    let signResult = safeSign(transcript)
    let handshakeSuccess = autograph_handshake_signature(
      &ourCiphertext,
      &ourSecretKey,
      &theirSecretKey,
      isInitiator ? 1 : 0,
      signResult.signature,
      &ephemeralKeyPair.privateKey,
      theirEphemeralKey
    ) == 0
    let establishSession: SessionFunction = createSession(
      sign: safeSign,
      theirPublicKey: theirIdentityKey,
      transcript: transcript,
      ourSecretKey: ourSecretKey,
      theirSecretKey: theirSecretKey
    )
    let handshake = Handshake(
      message: ourCiphertext,
      establishSession: establishSession
    )
    let success = transcriptSuccess && signResult.success && handshakeSuccess
    return HandshakeResult(success: success, handshake: handshake)
  }
  return performHandshake
}
