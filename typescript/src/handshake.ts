import { HandshakeFunction, KeyPair } from '../types'
import createSession from './session'
import { sign } from './crypto/sign'
import diffieHellman from './crypto/diffie-hellman'
import kdf from './crypto/kdf'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants'
import { concat } from 'stedy/bytes'
import { encrypt } from './crypto/aes'

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
  ourEphemeralPrivateKey: BufferSource,
  theirEphemeralPublicKey: BufferSource
): Promise<SecretKeys> => {
  const sharedSecret = await diffieHellman(
    ourEphemeralPrivateKey,
    theirEphemeralPublicKey
  )
  const a = await kdf(sharedSecret, CONTEXT_INITIATOR)
  const b = await kdf(sharedSecret, CONTEXT_RESPONDER)
  const [ourSecretKey, theirSecretKey] = isInitiator ? [a, b] : [b, a]
  return { ourSecretKey, theirSecretKey }
}

const createHandshake =
  (
    isInitiator: boolean,
    ourKeyPair: KeyPair,
    ourEphemeralKeyPair: KeyPair
  ): HandshakeFunction =>
  async (theirIdentityKey: BufferSource, theirEphemeralKey: BufferSource) => {
    const transcript = calculateTranscript(
      isInitiator,
      ourKeyPair.publicKey,
      ourEphemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    const signature = await sign(ourKeyPair.privateKey, transcript)
    const { ourSecretKey, theirSecretKey } = await deriveSecretKeys(
      isInitiator,
      ourEphemeralKeyPair.privateKey,
      theirEphemeralKey
    )
    const ciphertext = await encrypt(ourSecretKey, 0, signature)
    const establishSession = createSession(
      ourKeyPair.privateKey,
      theirIdentityKey,
      transcript,
      ourSecretKey,
      theirSecretKey
    )
    return { ciphertext, establishSession }
  }

export default createHandshake
