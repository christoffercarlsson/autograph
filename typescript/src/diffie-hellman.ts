import { diffieHellman as deriveSharedSecret } from 'stedy'
import { DH_OUTPUT_SIZE } from './constants'
import { importPrivateKey, importPublicKey } from './import-key'

const diffieHellman = async (
  ourPrivateKey: BufferSource,
  theirPublicKey: BufferSource
) =>
  deriveSharedSecret(
    await importPrivateKey(ourPrivateKey),
    await importPublicKey(theirPublicKey),
    DH_OUTPUT_SIZE
  )

export default diffieHellman
