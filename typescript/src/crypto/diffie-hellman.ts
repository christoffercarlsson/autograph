import { diffieHellman as deriveSharedSecret } from 'stedy'
import { DH_OUTPUT_SIZE } from '../constants'
import { importPrivateKey, importPublicKey } from '../utils'

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
