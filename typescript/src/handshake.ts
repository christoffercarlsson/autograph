import { HandshakeFunction, KeyPair } from '../types'
import createSession from './session'
import { sign } from './crypto/sign'
import diffieHellman from './crypto/diffie-hellman'
import kdf from './crypto/kdf'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants'
import { concat } from 'stedy/bytes'
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
  const a = await kdf(sharedSecret, CONTEXT_INITIATOR)
  const b = await kdf(sharedSecret, CONTEXT_RESPONDER)
  const [ourSecretKey, theirSecretKey] = isInitiator ? [a, b] : [b, a]
  return { ourSecretKey, theirSecretKey }
}

const createHandshake =
  (
    isInitiator: boolean,
    ourIdentityKeyPair: KeyPair,
    ourEphemeralKeyPair: KeyPair
  ): HandshakeFunction =>
  async (theirIdentityKey: BufferSource, theirEphemeralKey: BufferSource) => {
    const transcript = calculateTranscript(
      isInitiator,
      ourIdentityKeyPair.publicKey,
      ourEphemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    const signature = await sign(ourIdentityKeyPair.privateKey, transcript)
    const { ourSecretKey, theirSecretKey } = await deriveSecretKeys(
      isInitiator,
      ourEphemeralKeyPair.privateKey,
      theirEphemeralKey
    )
    const message = await encrypt(ourSecretKey, 0, signature)
    const establishSession = createSession(
      ourIdentityKeyPair.privateKey,
      theirIdentityKey,
      transcript,
      ourSecretKey,
      theirSecretKey
    )
    return { message, establishSession }
  }

export default createHandshake
