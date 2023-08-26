import Clibautograph
import Foundation

internal func createKeyExchange(
  isInitiator: Bool,
  sign: @escaping SignFunction,
  identityPublicKey: Bytes
) -> KeyExchangeFunction {
  let performKeyExchange: KeyExchangeFunction = { [
    isInitiator,
    sign,
    identityPublicKey
  ] ephemeralKeyPair, theirIdentityKey, theirEphemeralKey in
    let safeSign = createSafeSign(sign: sign)
    var handshake = createHandshakeBytes()
    var transcript = createTranscriptBytes()
    var ourSecretKey = createSecretKeyBytes()
    var theirSecretKey = createSecretKeyBytes()
    let transcriptSuccess = autograph_key_exchange_transcript(
      &transcript,
      isInitiator ? 1 : 0,
      identityPublicKey,
      ephemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    ) == 0
    let signResult = safeSign(transcript)
    let keyExchangeSuccess = autograph_key_exchange_signature(
      &handshake,
      &ourSecretKey,
      &theirSecretKey,
      isInitiator ? 1 : 0,
      signResult.signature,
      &ephemeralKeyPair.privateKey,
      theirEphemeralKey
    ) == 0
    let verify: KeyExchangeVerificationFunction = createKeyExchangeVerification(
      sign: safeSign,
      theirPublicKey: theirIdentityKey,
      transcript: transcript,
      ourSecretKey: ourSecretKey,
      theirSecretKey: theirSecretKey
    )
    let keyExchange = KeyExchange(
      handshake: handshake,
      verify: verify
    )
    let success = transcriptSuccess && signResult.success && keyExchangeSuccess
    return KeyExchangeResult(success: success, keyExchange: keyExchange)
  }
  return performKeyExchange
}

internal func createKeyExchangeVerification(
  sign: @escaping SignFunction,
  theirPublicKey: Bytes,
  transcript: Bytes,
  ourSecretKey: Bytes,
  theirSecretKey: Bytes
) -> KeyExchangeVerificationFunction {
  let verify: KeyExchangeVerificationFunction = { [
    sign,
    theirPublicKey,
    transcript,
    ourSecretKey,
    theirSecretKey
  ] theirCiphertext in
    let success = autograph_key_exchange_verify(
      transcript,
      theirPublicKey,
      theirSecretKey,
      theirCiphertext
    ) == 0
    let session = Session(
      decrypt: createDecrypt(theirSecretKey: theirSecretKey),
      encrypt: createEncrypt(ourSecretKey: ourSecretKey),
      signData: createSignData(
        sign: sign,
        theirPublicKey: theirPublicKey
      ),
      signIdentity: createSignIdentity(
        sign: sign,
        theirPublicKey: theirPublicKey
      ),
      verifyData: createVerifyData(
        theirPublicKey: theirPublicKey
      ),
      verifyIdentity: createVerifyIdentity(
        theirPublicKey: theirPublicKey
      )
    )
    return KeyExchangeVerificationResult(
      success: success,
      session: session
    )
  }
  return verify
}
