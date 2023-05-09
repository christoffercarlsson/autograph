import { fromInteger } from 'stedy/bytes'
import { createCipher } from 'stedy'
import {
  CHACHA20_POLY1305_CIPHER,
  CHACHA20_POLY1305_NONCE_SIZE
} from '../constants'

const { decrypt: decryptMessage, encrypt: encryptMessage } = createCipher(
  CHACHA20_POLY1305_CIPHER
)

export const decrypt = (
  key: BufferSource,
  index: number,
  ciphertext: BufferSource
) => {
  const nonce = fromInteger(index).padLeft(CHACHA20_POLY1305_NONCE_SIZE)
  return decryptMessage(key, nonce, ciphertext)
}

export const encrypt = (
  key: BufferSource,
  index: number,
  message: BufferSource
) => {
  const nonce = fromInteger(index).padLeft(CHACHA20_POLY1305_NONCE_SIZE)
  return encryptMessage(key, nonce, message)
}
