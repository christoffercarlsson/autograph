import { fromInteger } from 'stedy/bytes'
import { decrypt as decryptMessage } from 'stedy'
import { AES_GCM_NONCE_SIZE } from './constants'

const decrypt = (
  key: BufferSource,
  index: number,
  ciphertext: BufferSource
) => {
  const nonce = fromInteger(index).padLeft(AES_GCM_NONCE_SIZE)
  return decryptMessage(key, nonce, ciphertext)
}

export default decrypt
