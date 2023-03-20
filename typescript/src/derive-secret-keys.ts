import { CONTEXT_INITIATOR, CONTEXT_RESPONDER } from './constants'
import diffieHellman from './crypto/diffie-hellman'
import kdf from './crypto/kdf'

const deriveSecretKeys = async (
  isInitiator: boolean,
  ourEphemeralPrivateKey: BufferSource,
  theirEphemeralPublicKey: BufferSource
) => {
  const sharedSecret = await diffieHellman(
    ourEphemeralPrivateKey,
    theirEphemeralPublicKey
  )
  const a = await kdf(sharedSecret, CONTEXT_INITIATOR)
  const b = await kdf(sharedSecret, CONTEXT_RESPONDER)
  return isInitiator ? [a, b] : [b, a]
}

export default deriveSecretKeys
