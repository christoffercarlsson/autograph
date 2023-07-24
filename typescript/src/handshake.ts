import { alloc, concat } from 'stedy/bytes'
import {
  HandshakeFunction,
  HandshakeResult,
  KeyPair,
  SignFunction
} from '../types'
import createSession from './session'
import diffieHellman from './crypto/diffie-hellman'
import kdf from './crypto/kdf'
import { encrypt } from './crypto/cipher'
import { createErrorSignResult, ensureSignResult } from './utils'

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

const createHandshakeResult = (
  success: boolean,
  sign: SignFunction,
  theirIdentityPublicKey: BufferSource,
  transcript: BufferSource,
  message?: BufferSource,
  ourSecretKey?: BufferSource,
  theirSecretKey?: BufferSource
): HandshakeResult => {
  if (!success) {
    return {
      success,
      handshake: {
        message: alloc(80),
        establishSession: createSession(
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
    handshake: {
      message,
      establishSession: createSession(
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

const createHandshake =
  (
    isInitiator: boolean,
    sign: SignFunction,
    identityPublicKey: BufferSource
  ): HandshakeFunction =>
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
      const message = await encrypt(ourSecretKey, 0, signature)
      return createHandshakeResult(
        success,
        safeSign,
        theirIdentityKey,
        transcript,
        message,
        ourSecretKey,
        theirSecretKey
      )
    } catch (error) {
      return createHandshakeResult(
        false,
        safeSign,
        theirIdentityKey,
        transcript
      )
    }
  }

export default createHandshake
