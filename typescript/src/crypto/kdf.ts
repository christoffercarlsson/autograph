import { alloc, createFrom } from 'stedy/bytes'
import { hkdf } from 'stedy'

const kdf = (ikm: BufferSource, context: number) => {
  const salt = alloc(64)
  return hkdf(ikm, salt, createFrom([context]), 32)
}

export default kdf
