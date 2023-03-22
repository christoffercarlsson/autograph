import { sign } from 'stedy'
import { importPrivateSignKey } from './import-key'

const signMessage = async (
  ourPrivateKey: BufferSource,
  message: BufferSource
) => sign(await importPrivateSignKey(ourPrivateKey), message)

export default signMessage
