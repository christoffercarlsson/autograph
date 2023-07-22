import { alloc, concat, createFrom, fromInteger } from 'stedy/bytes'
import {
  CertifyFunction,
  DecryptFunction,
  EncryptFunction,
  SessionFunction,
  VerifyFunction
} from '../types'
import { decrypt, encrypt } from './crypto/cipher'
import { sign, verify as verifySignature } from './crypto/sign'

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
  async (data?: BufferSource) => {
    try {
      const signature = await sign(
        ourPrivateKey,
        concat([data, theirPublicKey])
      )
      return { success: true, signature }
    } catch (error) {
      return { success: false, signature: alloc(64) }
    }
  }

const createDecrypt =
  (theirSecretKey: BufferSource): DecryptFunction =>
  async (message: BufferSource) => {
    const [nonce, ciphertext] = createFrom(message).read(4)
    try {
      const data = await decrypt(
        theirSecretKey,
        nonce.readUint32BE(),
        ciphertext
      )
      return { success: true, data }
    } catch (error) {
      return {
        success: false,
        data: alloc(Math.max(ciphertext.byteLength - 16, 0))
      }
    }
  }

const createEncrypt = (ourSecretKey: BufferSource): EncryptFunction => {
  let index = 0
  return async (data: BufferSource) => {
    index += 1
    try {
      const ciphertext = await encrypt(ourSecretKey, index, data)
      const nonce = fromInteger(index)
      const message = concat([nonce, ciphertext])
      return { success: true, message }
    } catch (error) {
      return { success: false, message: alloc(data.byteLength + 16) }
    }
  }
}

const createVerify =
  (theirIdentityKey: BufferSource): VerifyFunction =>
  async (certificates: BufferSource, data?: BufferSource) => {
    try {
      const subject = concat([data, theirIdentityKey])
      const results = await Promise.all(
        createFrom(certificates)
          .split(96)
          .map((certificate) => {
            const [identityKey, signature] = certificate.read(32)
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
    const success = await verifySession(
      transcript,
      theirIdentityKey,
      theirSecretKey,
      message
    )
    const decrypt = createDecrypt(theirSecretKey)
    const certify = createCertify(ourPrivateKey, theirIdentityKey)
    const encrypt = createEncrypt(ourSecretKey)
    const verify = createVerify(theirIdentityKey)
    const session = {
      certify,
      decrypt,
      encrypt,
      verify
    }
    return { success, session }
  }

export default createSession
