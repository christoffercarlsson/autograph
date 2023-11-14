import {
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
} from './channel'
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
import { KeyExchangeError, KeyExchangeVerificationError } from './error'

const createKeyExchangeVerification =
  (
    sign: SignFunction,
    theirIdentityKey: Uint8Array,
    transcript: Uint8Array,
    ourSecretKey: Uint8Array,
    theirSecretKey: Uint8Array
  ): KeyExchangeVerificationFunction =>
  (theirHandshake: Uint8Array) => {
    const success = autograph_key_exchange_verify(
      transcript,
      theirIdentityKey,
      theirSecretKey,
      theirHandshake
    )
    if (!success) {
      throw new KeyExchangeVerificationError()
    }
    return {
      decrypt: createDecrypt(theirSecretKey),
      encrypt: createEncrypt(ourSecretKey),
      signData: createSignData(sign, theirIdentityKey),
      signIdentity: createSignIdentity(sign, theirIdentityKey),
      verifyData: createVerifyData(theirIdentityKey),
      verifyIdentity: createVerifyIdentity(theirIdentityKey)
    }
  }

const performKeyExchange = async (
  sign: SignFunction,
  identityPublicKey: Uint8Array,
  isInitiator: boolean,
  ourEphemeralKeyPair: KeyPair,
  theirIdentityKey: Uint8Array,
  theirEphemeralKey: Uint8Array
): Promise<[Uint8Array, KeyExchangeVerificationFunction]> => {
  const handshake = createHandshakeBytes()
  const transcript = createTranscriptBytes()
  const ourSecretKey = createSecretKeyBytes()
  const theirSecretKey = createSecretKeyBytes()
  const transcriptSuccess = autograph_key_exchange_transcript(
    transcript,
    isInitiator ? 1 : 0,
    identityPublicKey,
    ourEphemeralKeyPair.publicKey,
    theirIdentityKey,
    theirEphemeralKey
  )
  if (!transcriptSuccess) {
    throw new KeyExchangeError()
  }
  const signature = await sign(transcript)
  const keyExchangeSuccess = autograph_key_exchange_signature(
    handshake,
    ourSecretKey,
    theirSecretKey,
    isInitiator ? 1 : 0,
    signature,
    ourEphemeralKeyPair.privateKey,
    theirEphemeralKey
  )
  if (!keyExchangeSuccess) {
    throw new KeyExchangeError()
  }
  const verify: KeyExchangeVerificationFunction = createKeyExchangeVerification(
    sign,
    theirIdentityKey,
    transcript,
    ourSecretKey,
    theirSecretKey
  )
  return [handshake, verify]
}

export default performKeyExchange
