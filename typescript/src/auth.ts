import { autograph_authenticate } from './clib'
import { createSafetyNumber } from './support'

const authenticate = (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array
) => {
  const safetyNumber = createSafetyNumber()
  const success = autograph_authenticate(
    safetyNumber,
    ourIdentityKeyPair,
    theirIdentityKey
  )
  if (!success) {
    throw new Error('Authentication failed')
  }
  return safetyNumber
}

export default authenticate
