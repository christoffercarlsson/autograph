import { diffieHellman as deriveSharedSecret } from 'stedy'
import { importPrivateKey, importPublicKey } from '../utils'

const diffieHellman = async (
  ourPrivateKey: BufferSource,
  theirPublicKey: BufferSource
) =>
  deriveSharedSecret(
    await importPrivateKey(ourPrivateKey),
    await importPublicKey(theirPublicKey),
    32
  )

export default diffieHellman
