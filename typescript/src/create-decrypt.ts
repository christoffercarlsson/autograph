import { createFrom } from 'stedy/bytes'
import { DecryptFunction } from '../types'
import decrypt from './decrypt'

const createDecrypt =
  (theirSecretKey: BufferSource): DecryptFunction =>
  (message: BufferSource) => {
    const [nonce, ciphertext] = createFrom(message).read(4)
    return decrypt(theirSecretKey, nonce.readUint32BE(), ciphertext)
  }

export default createDecrypt
