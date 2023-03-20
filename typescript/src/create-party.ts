import { createFrom } from 'stedy/bytes'
import { KeyPair, Party } from '../types'
import createCalculateSafetyNumber from './create-calculate-safety-number'
import createHandshake from './create-handshake'
import { generateEphemeralKeyPair } from './generate-key-pair'

export const createParty = async (
  isInitiator: boolean,
  identityKeyPair: KeyPair
): Promise<Party> => {
  const ephemeralKeyPair = await generateEphemeralKeyPair()
  const calculateSafetyNumber = createCalculateSafetyNumber(
    identityKeyPair.publicKey
  )
  const handshake = createHandshake(
    isInitiator,
    identityKeyPair,
    ephemeralKeyPair
  )
  return {
    calculateSafetyNumber,
    ephemeralKey: createFrom(ephemeralKeyPair.publicKey),
    handshake,
    identityKey: createFrom(identityKeyPair.publicKey)
  }
}

export const createAlice = (identityKeyPair: KeyPair) =>
  createParty(true, identityKeyPair)

export const createBob = (identityKeyPair: KeyPair) =>
  createParty(false, identityKeyPair)
