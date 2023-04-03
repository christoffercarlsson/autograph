import { generateSignKeyPair as generateEd25519KeyPair } from 'stedy'
import { KeyPair } from '../types'
import {
  HANDSHAKE_SIZE,
  PRIVATE_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  SAFETY_NUMBER_SIZE,
  SIGNATURE_SIZE
} from './constants'
import createParty from './party'
import { exportKeyPair } from './utils'

const generateKeyPair = async () =>
  exportKeyPair(await generateEd25519KeyPair())

const createInitiator = (identityKeyPair: KeyPair) =>
  createParty(true, identityKeyPair)

const createResponder = (identityKeyPair: KeyPair) =>
  createParty(false, identityKeyPair)

export {
  HANDSHAKE_SIZE,
  PRIVATE_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  SAFETY_NUMBER_SIZE,
  SIGNATURE_SIZE,
  createInitiator,
  createResponder,
  generateKeyPair
}
