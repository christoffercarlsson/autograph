import { concat, createFrom, fromInteger } from 'stedy/bytes'
import {
  CertifyFunction,
  DecryptFunction,
  EncryptFunction,
  SessionFunction,
  VerifyFunction
} from '../types'
import { decrypt, encrypt } from './crypto/cipher'
import { sign, verify as verifySignature } from './crypto/sign'
import { PUBLIC_KEY_SIZE, SIGNATURE_SIZE } from './constants'

const verifySession = async (
  transcript: BufferSource,
  theirIdentityKey: BufferSource,
  theirSecretKey: BufferSource,
  message: BufferSource
) => {
  try {
    const signature = await decrypt(theirSecretKey, 0, message)
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
    theirPublicKey: BufferSource
  ): CertifyFunction =>
  async (data?: BufferSource) =>
    sign(ourPrivateKey, concat([data, theirPublicKey]))

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
  (theirIdentityKey: BufferSource): VerifyFunction =>
  async (certificates: BufferSource, data?: BufferSource) => {
    try {
      const subject = concat([data, theirIdentityKey])
      const results = await Promise.all(
        createFrom(certificates)
          .split(PUBLIC_KEY_SIZE + SIGNATURE_SIZE)
          .map((certificate) => {
            const [identityKey, signature] = certificate.read(PUBLIC_KEY_SIZE)
            return verifySignature(subject, identityKey, signature)
          })
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
  async (message: BufferSource) => {
    const verified = await verifySession(
      transcript,
      theirIdentityKey,
      theirSecretKey,
      message
    )
    if (!verified) {
      throw new Error('Handshake verification failed')
    }
    const decrypt = createDecrypt(theirSecretKey)
    const certify = createCertify(ourPrivateKey, theirIdentityKey)
    const encrypt = createEncrypt(ourSecretKey)
    const verify = createVerify(theirIdentityKey)
    return {
      certify,
      decrypt,
      encrypt,
      verify
    }
  }

export default createSession
