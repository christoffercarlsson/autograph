import {
  generateKeyPair as generateX25519KeyPair,
  generateSignKeyPair as generateEd25519KeyPair
} from 'stedy'
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

const generateIdentityKeyPair = async () =>
  exportKeyPair(await generateEd25519KeyPair())

const generateEphemeralKeyPair = async () =>
  exportKeyPair(await generateX25519KeyPair())

const createInitiator = async (
  identityKeyPair: KeyPair,
  ephemeralKeyPair?: KeyPair
) =>
  createParty(
    true,
    identityKeyPair,
    ephemeralKeyPair || (await generateEphemeralKeyPair())
  )

const createResponder = async (
  identityKeyPair: KeyPair,
  ephemeralKeyPair?: KeyPair
) =>
  createParty(
    false,
    identityKeyPair,
    ephemeralKeyPair || (await generateEphemeralKeyPair())
  )

export {
  HANDSHAKE_SIZE,
  PRIVATE_KEY_SIZE,
  PUBLIC_KEY_SIZE,
  SAFETY_NUMBER_SIZE,
  SIGNATURE_SIZE,
  createInitiator,
  createResponder,
  generateIdentityKeyPair,
  generateEphemeralKeyPair
}
