import { concat, createFrom } from 'stedy/bytes'
import { Certificate, DecryptFunction, VerifyFunction } from '../types'
import verifySignature from './verify-signature'

const verifySubject = async (
  certificates: Certificate[],
  data: BufferSource,
  theirIdentityKey: BufferSource
) => {
  try {
    const subject = concat([data, theirIdentityKey])
    const results = await Promise.all(
      certificates.map(({ identityKey, signature }) =>
        verifySignature(subject, identityKey, signature)
      )
    )
    return results.length > 0 && results.every((result) => result === true)
  } catch (error) {
    return false
  }
}

const createVerify =
  (theirIdentityKey: BufferSource, decrypt: DecryptFunction): VerifyFunction =>
  async (certificates: Certificate[], message?: BufferSource) => {
    const data = message ? await decrypt(message) : createFrom()
    return verifySubject(certificates, data, theirIdentityKey)
  }

export default createVerify
