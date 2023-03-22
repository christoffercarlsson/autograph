import { exportKey } from 'stedy'
import { KeyPair } from '../types'

const exportKeyPair = async ({
  publicKey,
  privateKey
}: KeyPair): Promise<KeyPair> => ({
  publicKey: await exportKey(publicKey),
  privateKey: await exportKey(privateKey)
})

export default exportKeyPair
