import { autograph_sign_subject } from './clib'
import { SignFunction, SignResult } from '../types'
import { createSignatureBytes } from './utils'

const createErrorSignResult = (): SignResult => ({
  success: false,
  signature: new Uint8Array(64)
})

const ensureSignResult = (result: SignResult): SignResult => {
  if (result.signature.byteLength !== 64) {
    return createErrorSignResult()
  }
  return result
}

export const createSafeSign =
  (sign: SignFunction): SignFunction =>
  async (subject: Uint8Array) => {
    try {
      const result = await sign(subject)
      return ensureSignResult(result)
    } catch (error) {
      return createErrorSignResult()
    }
  }

export const createSign =
  (identityPrivateKey: Uint8Array): SignFunction =>
  async (subject: Uint8Array) => {
    const signature = createSignatureBytes()
    const success = await autograph_sign_subject(
      signature,
      identityPrivateKey,
      subject,
      BigInt(subject.byteLength)
    )
    return { success, signature }
  }
