import { generateSignKeyPair as generateEd25519KeyPair } from 'stedy'
import { KeyPair } from '../types'
import { PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SIGNATURE_SIZE } from './constants'
import createParty from './create-party'
import exportKeyPair from './export-key-pair'

const createAlice = (identityKeyPair: KeyPair) =>
  createParty(true, identityKeyPair)

const createBob = (identityKeyPair: KeyPair) =>
  createParty(false, identityKeyPair)

const createInitiator = (identityKeyPair: KeyPair) =>
  createAlice(identityKeyPair)

const createResponder = (identityKeyPair: KeyPair) => createBob(identityKeyPair)

const generateKeyPair = async () =>
  exportKeyPair(await generateEd25519KeyPair())

const generateParty = async (isInitiator: boolean) => {
  const keyPair = await generateKeyPair()
  return createParty(isInitiator, keyPair)
}

const generateAlice = () => generateParty(true)

const generateBob = () => generateParty(false)

const generateInitiator = () => generateAlice()

const generateResponder = () => generateBob()

export {
  PRIVATE_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE,
  createAlice,
  createBob,
  createInitiator,
  createResponder,
  generateAlice,
  generateBob,
  generateInitiator,
  generateKeyPair,
  generateResponder
}
