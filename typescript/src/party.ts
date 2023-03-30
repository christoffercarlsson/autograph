import { createFrom } from 'stedy/bytes'
import { KeyPair, Party } from '../types'
import createHandshake from './handshake'
import { generateEphemeralKeyPair } from './key-pair'
import createSafetyNumber from './safety-number'

const createParty = async (
  isInitiator: boolean,
  identityKeyPair: KeyPair
): Promise<Party> => {
  const ephemeralKeyPair = await generateEphemeralKeyPair()
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
