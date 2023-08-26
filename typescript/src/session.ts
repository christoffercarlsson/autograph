import { alloc, concat, createFrom } from 'stedy/bytes'
import {
  DecryptFunction,
  EncryptFunction,
  SignFunction,
  SignDataFunction,
  SignIdentityFunction,
  VerifyDataFunction,
  VerifyIdentityFunction
} from '../types'
import { decrypt, encrypt } from './crypto/cipher'
import { verify as verifySignature } from './crypto/sign'
import { createErrorSignResult, ensureSignResult } from './utils'

export const createDecrypt =
  (theirSecretKey: BufferSource): DecryptFunction =>
  async (message: BufferSource) => {
    const [nonce, ciphertext] = createFrom(message).read(8)
    try {
      const data = await decrypt(
        theirSecretKey,
        nonce.readUint64BE() as bigint,
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

export const createEncrypt = (ourSecretKey: BufferSource): EncryptFunction => {
  let index = 0n
  return async (data: BufferSource) => {
    index += 1n
    try {
      const ciphertext = await encrypt(ourSecretKey, index, data)
      const nonce = alloc(8).writeUint64BE(index)
      const message = concat([nonce, ciphertext])
      return { success: true, message }
    } catch (error) {
      return { success: false, message: alloc(data.byteLength + 24) }
    }
  }
}

export const createSignData =
  (sign: SignFunction, theirPublicKey: BufferSource): SignDataFunction =>
  async (data: BufferSource) => {
    try {
      const result = await sign(concat([data, theirPublicKey]))
      return ensureSignResult(result)
    } catch (error) {
      return createErrorSignResult()
    }
  }

export const createSignIdentity =
  (sign: SignFunction, theirPublicKey: BufferSource): SignIdentityFunction =>
  async () => {
    try {
      const result = await sign(theirPublicKey)
      return ensureSignResult(result)
    } catch (error) {
      return createErrorSignResult()
    }
  }

const verifyCertificates = async (
  certificates: BufferSource,
  subject: BufferSource
) => {
  try {
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

export const createVerifyData =
  (theirIdentityKey: BufferSource): VerifyDataFunction =>
  (certificates: BufferSource, data: BufferSource) =>
    verifyCertificates(certificates, concat([data, theirIdentityKey]))

export const createVerifyIdentity =
  (theirIdentityKey: BufferSource): VerifyIdentityFunction =>
  async (certificates: BufferSource) =>
    verifyCertificates(certificates, theirIdentityKey)
