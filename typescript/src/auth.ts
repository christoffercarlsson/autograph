import { autograph_authenticate, autograph_safety_number_size } from './clib'

const createSafetyNumber = () => new Uint8Array(autograph_safety_number_size())

const authenticate = (
  ourIdentityKeyPair: Uint8Array,
  ourId: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirId: Uint8Array
) => {
  const safetyNumber = createSafetyNumber()
  const success = autograph_authenticate(
    safetyNumber,
    ourIdentityKeyPair,
    ourId,
    ourId.byteLength,
    theirIdentityKey,
    theirId,
    theirId.byteLength
  )
  if (!success) {
    throw new Error('Authentication failed')
  }
  return safetyNumber
}

export default authenticate
