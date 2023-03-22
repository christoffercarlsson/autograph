import { HandshakeFunction, KeyPair } from '../types'
import createSession from './create-session'
import encrypt from './encrypt'
import deriveSecretKeys from './derive-secret-keys'
import getTranscript from './get-transcript'
import signMessage from './sign-message'

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
    const signature = await signMessage(ourKeyPair.privateKey, transcript)
    const secretKeys = await deriveSecretKeys(
      isInitiator,
      ourEphemeralKeyPair.privateKey,
      theirEphemeralKey
    )
    const ciphertext = await encrypt(secretKeys.ourSecretKey, 0, signature)
    const session = createSession(
      ourKeyPair.privateKey,
      theirIdentityKey,
      transcript,
      secretKeys
    )
    return { ciphertext, session }
  }

export default createHandshake
