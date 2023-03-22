import { concat, fromInteger } from 'stedy/bytes'
import { EncryptFunction } from '../types'
import encrypt from './encrypt'

const createEncrypt = (ourSecretKey: BufferSource): EncryptFunction => {
  let index = 0
  return async (message: BufferSource) => {
    index += 1
    const ciphertext = await encrypt(ourSecretKey, index, message)
    const nonce = fromInteger(index)
    return concat([nonce, ciphertext])
  }
}

export default createEncrypt
