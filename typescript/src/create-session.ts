import { SecretKeys, SessionFunction } from '../types'
import createCertify from './create-certify'
import createDecrypt from './create-decrypt'
import createEncrypt from './create-encrypt'
import createVerify from './create-verify'
import verifyTranscript from './verify-transcript'

const createSession =
  (
    ourPrivateKey: BufferSource,
    theirIdentityKey: BufferSource,
    transcript: BufferSource,
    { ourSecretKey, theirSecretKey }: SecretKeys
  ): SessionFunction =>
  async (ciphertext: BufferSource) => {
    const verified = await verifyTranscript(
      transcript,
      theirIdentityKey,
      theirSecretKey,
      ciphertext
    )
    if (!verified) {
      throw new Error('Handshake verification failed')
    }
    const certify = createCertify(ourPrivateKey, theirIdentityKey)
    const decrypt = createDecrypt(theirSecretKey)
    const encrypt = createEncrypt(ourSecretKey)
    const verify = createVerify(theirIdentityKey, decrypt)
    return {
      certify,
      decrypt,
      encrypt,
      verify
    }
  }

export default createSession
