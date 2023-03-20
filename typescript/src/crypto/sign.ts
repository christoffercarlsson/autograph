import { sign as signMessage } from 'stedy'
import { importPrivateSignKey } from './import-key'

const sign = async (ourPrivateKey: BufferSource, message: BufferSource) =>
  signMessage(await importPrivateSignKey(ourPrivateKey), message)

export default sign
