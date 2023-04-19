import { concat, createFrom, fromInteger } from 'stedy/bytes'
import {
  Certificate,
  CertifyFunction,
  DecryptFunction,
  EncryptFunction,
  SessionFunction,
  VerifyFunction
} from '../types'
import { decrypt, encrypt } from './crypto/aes'
import { sign, verify as verifySignature } from './crypto/sign'

const verifySession = async (
  transcript: BufferSource,
  theirIdentityKey: BufferSource,
  theirSecretKey: BufferSource,
  ciphertext: BufferSource
) => {
  try {
    const signature = await decrypt(theirSecretKey, 0, ciphertext)
    const verified = await verifySignature(
      transcript,
      theirIdentityKey,
      signature
    )
    return verified
  } catch (error) {
    return false
  }
}

const createCertify =
  (
    ourPrivateKey: BufferSource,
    theirPublicKey: BufferSource,
    decrypt: DecryptFunction
  ): CertifyFunction =>
  async (message?: BufferSource) => {
    const data = message ? await decrypt(message) : createFrom([])
    return sign(ourPrivateKey, concat([data, theirPublicKey]))
  }

const createDecrypt =
  (theirSecretKey: BufferSource): DecryptFunction =>
  (message: BufferSource) => {
    const [nonce, ciphertext] = createFrom(message).read(4)
    return decrypt(theirSecretKey, nonce.readUint32BE(), ciphertext)
  }

const createEncrypt = (ourSecretKey: BufferSource): EncryptFunction => {
  let index = 0
  return async (message: BufferSource) => {
    index += 1
    const ciphertext = await encrypt(ourSecretKey, index, message)
    const nonce = fromInteger(index)
    return concat([nonce, ciphertext])
  }
}

const createVerify =
  (theirIdentityKey: BufferSource, decrypt: DecryptFunction): VerifyFunction =>
  async (certificates: Certificate[] | Certificate, message?: BufferSource) => {
    try {
      const data = message ? await decrypt(message) : createFrom()
      const subject = concat([data, theirIdentityKey])
      const results = await Promise.all(
        (Array.isArray(certificates) ? certificates : [certificates]).map(
          ({ identityKey, signature }) =>
            verifySignature(subject, identityKey, signature)
        )
      )
      return results.length > 0 && results.every((result) => result === true)
    } catch (error) {
      return false
    }
  }

const createSession =
  (
    ourPrivateKey: BufferSource,
    theirIdentityKey: BufferSource,
    transcript: BufferSource,
    ourSecretKey: BufferSource,
    theirSecretKey: BufferSource
  ): SessionFunction =>
  async (handshake: BufferSource) => {
    const verified = await verifySession(
      transcript,
      theirIdentityKey,
      theirSecretKey,
      handshake
    )
    if (!verified) {
      throw new Error('Handshake verification failed')
    }
    const decrypt = createDecrypt(theirSecretKey)
    const certify = createCertify(ourPrivateKey, theirIdentityKey, decrypt)
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
