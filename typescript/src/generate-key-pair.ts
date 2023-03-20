import {
  exportKey,
  generateKeyPair as generateX25519KeyPair,
  generateSignKeyPair as generateEd25519KeyPair
} from 'stedy'
import { KeyPair } from '../types'

const exportKeyPair = async ({
  publicKey,
  privateKey
}: KeyPair): Promise<KeyPair> => ({
  publicKey: await exportKey(publicKey),
  privateKey: await exportKey(privateKey)
})

export const generateEphemeralKeyPair = async () =>
  exportKeyPair(await generateX25519KeyPair())

export const generateKeyPair = async () =>
  exportKeyPair(await generateEd25519KeyPair())
