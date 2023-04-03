import { generateKeyPair as generateX25519KeyPair } from 'stedy'
import { createFrom } from 'stedy/bytes'
import { KeyPair, Party } from '../types'
import createHandshake from './handshake'
import createSafetyNumber from './safety-number'
import { exportKeyPair } from './utils'

const generateEphemeralKeyPair = async () =>
  exportKeyPair(await generateX25519KeyPair())

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
