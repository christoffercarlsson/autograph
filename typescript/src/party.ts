import { KeyPair, Party } from '../types'
import createHandshake from './handshake'
import createSafetyNumber from './safety-number'

const createParty = (isInitiator: boolean, identityKeyPair: KeyPair): Party => {
  const calculateSafetyNumber = createSafetyNumber(identityKeyPair.publicKey)
  const performHandshake = createHandshake(isInitiator, identityKeyPair)
  return {
    calculateSafetyNumber,
    performHandshake
  }
}

export default createParty
