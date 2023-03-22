import { fromInteger } from 'stedy/bytes'
import { encrypt as encryptMessage } from 'stedy'
import { AES_GCM_NONCE_SIZE } from './constants'

const encrypt = (key: BufferSource, index: number, message: BufferSource) => {
  const nonce = fromInteger(index).padLeft(AES_GCM_NONCE_SIZE)
  return encryptMessage(key, nonce, message)
}

export default encrypt
