import { fromInteger } from 'stedy/bytes'
import { createCipher } from 'stedy'

const { decrypt: decryptMessage, encrypt: encryptMessage } =
  createCipher('ChaCha20-Poly1305')

const indexToNonce = (index: number) => fromInteger(index).padLeft(12)

export const decrypt = (
  key: BufferSource,
  index: number,
  ciphertext: BufferSource
) => {
  const nonce = indexToNonce(index)
  return decryptMessage(key, nonce, ciphertext)
}

export const encrypt = (
  key: BufferSource,
  index: number,
  message: BufferSource
) => {
  const nonce = indexToNonce(index)
  return encryptMessage(key, nonce, message)
}
