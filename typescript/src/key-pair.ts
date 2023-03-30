import {
  generateKeyPair as generateX25519KeyPair,
  generateSignKeyPair as generateEd25519KeyPair
} from 'stedy'
import { exportKeyPair } from './utils'

export const generateEphemeralKeyPair = async () =>
  exportKeyPair(await generateX25519KeyPair())

export const generateKeyPair = async () =>
  exportKeyPair(await generateEd25519KeyPair())
