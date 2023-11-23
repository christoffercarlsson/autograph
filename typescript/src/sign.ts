import { autograph_sign_subject } from './clib'
import { SignFunction } from '../../types'
import { createSignatureBytes } from './utils'
import { SigningError } from './error'

const createSign =
  (identityPrivateKey: Uint8Array): SignFunction =>
  (subject: Uint8Array) => {
    const signature = createSignatureBytes()
    const success =
      autograph_sign_subject(
        signature,
        identityPrivateKey,
        subject,
        subject.byteLength
      ) === 0
    if (!success) {
      throw new SigningError()
    }
    return signature
  }

export default createSign
