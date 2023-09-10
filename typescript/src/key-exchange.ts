import {
  KeyExchangeFunction,
  KeyExchangeVerificationFunction,
  KeyPair,
  SignFunction
} from '../types'

import {
  createDecrypt,
  createEncrypt,
  createSignData,
  createSignIdentity,
  createVerifyData,
  createVerifyIdentity
} from './session'
import { createSafeSign } from './sign'
import {
  autograph_key_exchange_signature,
  autograph_key_exchange_transcript,
  autograph_key_exchange_verify
} from './clib'
import {
  createHandshakeBytes,
  createSecretKeyBytes,
  createTranscriptBytes
} from './utils'

const createKeyExchange =
  (
    isInitiator: boolean,
    sign: SignFunction,
    identityPublicKey: Uint8Array
  ): KeyExchangeFunction =>
  async (
    ourEphemeralKeyPair: KeyPair,
    theirIdentityKey: Uint8Array,
    theirEphemeralKey: Uint8Array
  ) => {
    const safeSign = createSafeSign(sign)
    const handshake = createHandshakeBytes()
    const transcript = createTranscriptBytes()
    const ourSecretKey = createSecretKeyBytes()
    const theirSecretKey = createSecretKeyBytes()
    const transcriptSuccess = await autograph_key_exchange_transcript(
      transcript,
      isInitiator ? 1 : 0,
      identityPublicKey,
      ourEphemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    const { success: signSuccess, signature } = await safeSign(transcript)
    const keyExchangeSuccess = await autograph_key_exchange_signature(
      handshake,
      ourSecretKey,
      theirSecretKey,
      isInitiator ? 1 : 0,
      signature,
      ourEphemeralKeyPair.privateKey,
      theirEphemeralKey
    )
    const verify: KeyExchangeVerificationFunction =
      createKeyExchangeVerification(
        safeSign,
        theirIdentityKey,
        transcript,
        ourSecretKey,
        theirSecretKey
      )
    return {
      success: transcriptSuccess && signSuccess && keyExchangeSuccess,
      keyExchange: { handshake, verify }
    }
  }

const createKeyExchangeVerification =
  (
    sign: SignFunction,
    theirIdentityKey: Uint8Array,
    transcript: Uint8Array,
    ourSecretKey: Uint8Array,
    theirSecretKey: Uint8Array
  ): KeyExchangeVerificationFunction =>
  async (handshake: Uint8Array) => {
    const success = await autograph_key_exchange_verify(
      transcript,
      theirIdentityKey,
      theirSecretKey,
      handshake
    )
    const session = {
      decrypt: createDecrypt(theirSecretKey),
      encrypt: createEncrypt(ourSecretKey),
      signData: createSignData(sign, theirIdentityKey),
      signIdentity: createSignIdentity(sign, theirIdentityKey),
      verifyData: createVerifyData(theirIdentityKey),
      verifyIdentity: createVerifyIdentity(theirIdentityKey)
    }
    return { success, session }
  }

export default createKeyExchange
