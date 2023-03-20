import { HandshakeFunction, KeyPair } from '../types'
import createSession from './create-session'
import encrypt from './crypto/encrypt'
import sign from './crypto/sign'
import deriveSecretKeys from './derive-secret-keys'
import getTranscript from './get-transcript'

const createHandshake =
  (
    isInitiator: boolean,
    ourKeyPair: KeyPair,
    ourEphemeralKeyPair: KeyPair
  ): HandshakeFunction =>
  async (theirIdentityKey: BufferSource, theirEphemeralKey: BufferSource) => {
    const transcript = getTranscript(
      isInitiator,
      ourKeyPair.publicKey,
      ourEphemeralKeyPair.publicKey,
      theirIdentityKey,
      theirEphemeralKey
    )
    const signature = await sign(ourKeyPair.privateKey, transcript)
    const [ourSecretKey, theirSecretKey] = await deriveSecretKeys(
      isInitiator,
      ourEphemeralKeyPair.privateKey,
      theirEphemeralKey
    )
    const ciphertext = await encrypt(ourSecretKey, 0, signature)
    const session = createSession(
      ourKeyPair.privateKey,
      theirIdentityKey,
      transcript,
      ourSecretKey,
      theirSecretKey
    )
    return { ciphertext, session }
  }

export default createHandshake
