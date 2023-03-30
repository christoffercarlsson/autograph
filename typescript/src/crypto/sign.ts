import { sign as signMessage, verify as verifySignature } from 'stedy'
import { importPrivateSignKey, importPublicSignKey } from '../utils'

export const sign = async (
  ourPrivateKey: BufferSource,
  message: BufferSource
) => signMessage(await importPrivateSignKey(ourPrivateKey), message)

export const verify = async (
  message: BufferSource,
  publicKey: BufferSource,
  signature: BufferSource
) => verifySignature(message, await importPublicSignKey(publicKey), signature)
