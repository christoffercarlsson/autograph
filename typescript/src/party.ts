import { Party, SignFunction } from '../types'
import createKeyExchange from './key-exchange'
import createSafetyNumber from './safety-number'

const createParty = (
  isInitiator: boolean,
  sign: SignFunction,
  identityPublicKey: Uint8Array
): Party => ({
  calculateSafetyNumber: createSafetyNumber(identityPublicKey),
  performKeyExchange: createKeyExchange(isInitiator, sign, identityPublicKey)
})

export default createParty
