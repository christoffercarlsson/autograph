import { Party, SignFunction } from '../types'
import createHandshake from './handshake'
import createSafetyNumber from './safety-number'

const createParty = (
  isInitiator: boolean,
  sign: SignFunction,
  identityPublicKey: BufferSource
): Party => {
  const calculateSafetyNumber = createSafetyNumber(identityPublicKey)
  const performHandshake = createHandshake(isInitiator, sign, identityPublicKey)
  return {
    calculateSafetyNumber,
    performHandshake
  }
}

export default createParty
