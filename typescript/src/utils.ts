import { exportKey, importKey } from 'stedy'
import { KeyPair, SignResult } from '../types'
import { alloc } from 'stedy/bytes'

export const createErrorSignResult = (): SignResult => ({
  success: false,
  signature: alloc(64)
})

export const ensureSignResult = (result: SignResult): SignResult => {
  if (result.signature.byteLength !== 64) {
    return createErrorSignResult()
  }
  return result
}

export const exportKeyPair = async ({
  publicKey,
  privateKey
}: KeyPair): Promise<KeyPair> => ({
  publicKey: await exportKey(publicKey),
  privateKey: await exportKey(privateKey)
})

export const importPrivateKey = (key: BufferSource) =>
  importKey(key, false, false)

export const importPrivateSignKey = (key: BufferSource) =>
  importKey(key, true, false)

export const importPublicKey = (key: BufferSource) =>
  importKey(key, false, true)

export const importPublicSignKey = (key: BufferSource) =>
  importKey(key, true, true)
