import { generateKeyPair as generateX25519KeyPair } from 'stedy'
import exportKeyPair from './export-key-pair'

const generateEphemeralKeyPair = async () =>
  exportKeyPair(await generateX25519KeyPair())

export default generateEphemeralKeyPair
