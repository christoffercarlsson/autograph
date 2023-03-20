import { verify as verifyMessage } from 'stedy'
import { importPublicSignKey } from './import-key'

const verify = async (
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource
) => verifyMessage(message, await importPublicSignKey(publicKey), signature)

export default verify
