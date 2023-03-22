import { SecretKeys } from '../types'
import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants'
import diffieHellman from './diffie-hellman'
import kdf from './kdf'

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

export default deriveSecretKeys
