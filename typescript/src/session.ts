import {
  DecryptFunction,
  EncryptFunction,
  SignFunction,
  SignDataFunction,
  SignIdentityFunction,
  VerifyDataFunction,
  VerifyIdentityFunction
} from '../types'
import { createMessageBytes, createPlaintextBytes } from './utils'
import {
  autograph_decrypt,
  autograph_encrypt,
  autograph_verify_data,
  autograph_verify_identity
} from './clib'

export const createDecrypt =
  (theirSecretKey: Uint8Array): DecryptFunction =>
  async (message: Uint8Array) => {
    const data = createPlaintextBytes(message.byteLength)
    const success = await autograph_decrypt(
      data,
      theirSecretKey,
      message,
      BigInt(message.byteLength)
    )
    return { success, data }
  }

export const createEncrypt = (ourSecretKey: Uint8Array): EncryptFunction => {
  let index = 0n
  return async (data: Uint8Array) => {
    index += 1n
    const message = createMessageBytes(data.byteLength)
    const success = await autograph_encrypt(
      message,
      ourSecretKey,
      index,
      data,
      BigInt(data.byteLength)
    )
    return { success, message }
  }
}

export const createSignData =
  (sign: SignFunction, theirPublicKey: Uint8Array): SignDataFunction =>
  async (data: Uint8Array) => {
    const subject = new Uint8Array(data.byteLength + theirPublicKey.byteLength)
    subject.set(data)
    subject.set(theirPublicKey, data.byteLength)
    return sign(subject)
  }

export const createSignIdentity =
  (sign: SignFunction, theirPublicKey: Uint8Array): SignIdentityFunction =>
  async () =>
    sign(theirPublicKey)

const countCertificates = (certificates: Uint8Array) =>
  BigInt(certificates.byteLength / 96)

export const createVerifyData =
  (theirIdentityKey: Uint8Array): VerifyDataFunction =>
  (certificates: Uint8Array, data: Uint8Array) =>
    autograph_verify_data(
      theirIdentityKey,
      certificates,
      countCertificates(certificates),
      data,
      BigInt(data.byteLength)
    )

export const createVerifyIdentity =
  (theirIdentityKey: Uint8Array): VerifyIdentityFunction =>
  async (certificates: Uint8Array) =>
    autograph_verify_identity(
      theirIdentityKey,
      certificates,
      countCertificates(certificates)
    )
