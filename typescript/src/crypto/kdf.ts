import { alloc, createFrom } from 'stedy/bytes'
import { hkdf } from 'stedy'
import { HKDF_SALT_SIZE, SECRET_KEY_SIZE } from '../constants'

const kdf = (ikm: BufferSource, context: number) => {
  const salt = alloc(HKDF_SALT_SIZE)
  return hkdf(ikm, salt, createFrom([context]), SECRET_KEY_SIZE)
}

export default kdf
