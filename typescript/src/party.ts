import { createFrom } from 'stedy/bytes'
import { KeyPair, Party } from '../types'
import createHandshake from './handshake'
import createSafetyNumber from './safety-number'

const createParty = (
  isInitiator: boolean,
  identityKeyPair: KeyPair,
  ephemeralKeyPair: KeyPair
): Party => {
  const calculateSafetyNumber = createSafetyNumber(identityKeyPair.publicKey)
  const performHandshake = createHandshake(
    isInitiator,
    identityKeyPair,
    ephemeralKeyPair
  )
  return {
    calculateSafetyNumber,
    ephemeralKey: createFrom(ephemeralKeyPair.publicKey),
    performHandshake,
    identityKey: createFrom(identityKeyPair.publicKey)
  }
}

export default createParty
