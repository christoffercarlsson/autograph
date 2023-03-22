import { verify } from 'stedy'
import { importPublicSignKey } from './import-key'

const verifySignature = async (
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource
) => verify(message, await importPublicSignKey(publicKey), signature)

export default verifySignature
