import { alloc, concat } from 'stedy/bytes'
import { HandshakeFunction, HandshakeResult, KeyPair } from '../types'
import createSession from './session'
import { sign } from './crypto/sign'
import diffieHellman from './crypto/diffie-hellman'
import kdf from './crypto/kdf'
import { encrypt } from './crypto/cipher'

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
  ourIdentityPrivateKey: BufferSource,
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
          ourIdentityPrivateKey,
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
        ourIdentityPrivateKey,
        theirIdentityPublicKey,
        transcript,
        ourSecretKey,
        theirSecretKey
      )
    }
  }
}

const createHandshake =
  (isInitiator: boolean, ourIdentityKeyPair: KeyPair): HandshakeFunction =>
  async (
    ourEphemeralKeyPair: KeyPair,
    theirIdentityKey: BufferSource,
    theirEphemeralKey: BufferSource
  ) => {
    const transcript = calculateTranscript(
      isInitiator,
      ourIdentityKeyPair.publicKey,
      ourEphemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    try {
      const signature = await sign(ourIdentityKeyPair.privateKey, transcript)
      const { ourSecretKey, theirSecretKey } = await deriveSecretKeys(
        isInitiator,
        ourEphemeralKeyPair.privateKey,
        theirEphemeralKey
      )
      const message = await encrypt(ourSecretKey, 0, signature)
      return createHandshakeResult(
        true,
        ourIdentityKeyPair.privateKey,
        theirIdentityKey,
        transcript,
        message,
        ourSecretKey,
        theirSecretKey
      )
    } catch (error) {
      return createHandshakeResult(
        false,
        ourIdentityKeyPair.privateKey,
        theirIdentityKey,
        transcript
      )
    }
  }

export default createHandshake
