import { alloc } from 'stedy/bytes'
import { createCipher } from 'stedy'

const { decrypt: decryptMessage, encrypt: encryptMessage } =
  createCipher('ChaCha20-Poly1305')

const indexToNonce = (index: bigint) =>
  alloc(8).writeUint64BE(index).padLeft(12)

export const decrypt = (
  key: BufferSource,
  index: bigint,
  ciphertext: BufferSource
) => {
  const nonce = indexToNonce(index)
  return decryptMessage(key, nonce, ciphertext)
}

export const encrypt = (
  key: BufferSource,
  index: bigint,
  message: BufferSource
) => {
  const nonce = indexToNonce(index)
  return encryptMessage(key, nonce, message)
}
