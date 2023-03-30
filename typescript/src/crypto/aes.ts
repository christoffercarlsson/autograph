import { fromInteger } from 'stedy/bytes'
import { decrypt as decryptMessage, encrypt as encryptMessage } from 'stedy'
import { AES_GCM_NONCE_SIZE } from '../constants'

export const decrypt = (
  key: BufferSource,
  index: number,
  ciphertext: BufferSource
) => {
  const nonce = fromInteger(index).padLeft(AES_GCM_NONCE_SIZE)
  return decryptMessage(key, nonce, ciphertext)
}

export const encrypt = (
  key: BufferSource,
  index: number,
  message: BufferSource
) => {
  const nonce = fromInteger(index).padLeft(AES_GCM_NONCE_SIZE)
  return encryptMessage(key, nonce, message)
}
