import { alloc, concat } from 'stedy/bytes'
import {
  KeyExchangeFunction,
  KeyExchangeResult,
  KeyExchangeVerificationFunction,
  KeyPair,
  SignFunction
} from '../types'
import diffieHellman from './crypto/diffie-hellman'
import kdf from './crypto/kdf'
import { decrypt, encrypt } from './crypto/cipher'
import { verify as verifySignature } from './crypto/sign'
import { createErrorSignResult, ensureSignResult } from './utils'
import {
  createDecrypt,
  createEncrypt,
  createSignData,
  createSignIdentity,
  createVerifyData,
  createVerifyIdentity
} from './session'

type SecretKeys = {
  ourSecretKey: BufferSource
  theirSecretKey: BufferSource
}

const calculateTranscript = (
  isInitiator: boolean,
  ourIdentityKey: BufferSource,
  ourEphemeralKey: BufferSource,
  theirIdentityKey: BufferSource,
  theirEphemeralKey: BufferSource
) =>
  concat(
    isInitiator
      ? [ourIdentityKey, theirIdentityKey, ourEphemeralKey, theirEphemeralKey]
      : [theirIdentityKey, ourIdentityKey, theirEphemeralKey, ourEphemeralKey]
  )

const deriveSecretKeys = async (
  isInitiator: boolean,
  ourPrivateKey: BufferSource,
  theirPublicKey: BufferSource
): Promise<SecretKeys> => {
  const sharedSecret = await diffieHellman(ourPrivateKey, theirPublicKey)
  const a = await kdf(sharedSecret, 0)
  const b = await kdf(sharedSecret, 1)
  const [ourSecretKey, theirSecretKey] = isInitiator ? [a, b] : [b, a]
  return { ourSecretKey, theirSecretKey }
}

const verifyHandshake = async (
  transcript: BufferSource,
  theirIdentityKey: BufferSource,
  theirSecretKey: BufferSource,
  handshake: BufferSource
) => {
  try {
    const signature = await decrypt(theirSecretKey, 0n, handshake)
    const verified = await verifySignature(
      transcript,
      theirIdentityKey,
      signature
    )
    return verified
  } catch (error) {
    return false
  }
}

const createKeyExchangeVerification =
  (
    sign: SignFunction,
    theirIdentityKey: BufferSource,
    transcript: BufferSource,
    ourSecretKey: BufferSource,
    theirSecretKey: BufferSource
  ): KeyExchangeVerificationFunction =>
  async (handshake: BufferSource) => {
    const success = await verifyHandshake(
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

const createKeyExchangeResult = (
  success: boolean,
  sign: SignFunction,
  theirIdentityPublicKey: BufferSource,
  transcript: BufferSource,
  handshake?: BufferSource,
  ourSecretKey?: BufferSource,
  theirSecretKey?: BufferSource
): KeyExchangeResult => {
  if (!success) {
    return {
      success,
      keyExchange: {
        handshake: alloc(80),
        verify: createKeyExchangeVerification(
          sign,
          theirIdentityPublicKey,
          transcript,
          alloc(32),
          alloc(32)
        )
      }
    }
  }
  return {
    success,
    keyExchange: {
      handshake,
      verify: createKeyExchangeVerification(
        sign,
        theirIdentityPublicKey,
        transcript,
        ourSecretKey,
        theirSecretKey
      )
    }
  }
}

const createSafeSign =
  (sign: SignFunction): SignFunction =>
  async (subject: BufferSource) => {
    try {
      const result = await sign(subject)
      return ensureSignResult(result)
    } catch (error) {
      return createErrorSignResult()
    }
  }

const createKeyExchange =
  (
    isInitiator: boolean,
    sign: SignFunction,
    identityPublicKey: BufferSource
  ): KeyExchangeFunction =>
  async (
    ourEphemeralKeyPair: KeyPair,
    theirIdentityKey: BufferSource,
    theirEphemeralKey: BufferSource
  ) => {
    const safeSign = createSafeSign(sign)
    const transcript = calculateTranscript(
      isInitiator,
      identityPublicKey,
      ourEphemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    try {
      const { success, signature } = await safeSign(transcript)
      const { ourSecretKey, theirSecretKey } = await deriveSecretKeys(
        isInitiator,
        ourEphemeralKeyPair.privateKey,
        theirEphemeralKey
      )
      const handshake = await encrypt(ourSecretKey, 0n, signature)
      return createKeyExchangeResult(
        success,
        safeSign,
        theirIdentityKey,
        transcript,
        handshake,
        ourSecretKey,
        theirSecretKey
      )
    } catch (error) {
      return createKeyExchangeResult(
        false,
        safeSign,
        theirIdentityKey,
        transcript
      )
    }
  }

export default createKeyExchange
