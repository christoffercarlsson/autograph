import {
  DecryptFunction,
  EncryptFunction,
  SignFunction,
  SignDataFunction,
  SignIdentityFunction,
  VerifyDataFunction,
  VerifyIdentityFunction
} from '../types'
import {
  bytesToIndex,
  createMessageBytes,
  createPlaintextBytes,
  createSubjectBytes
} from './utils'
import {
  autograph_decrypt,
  autograph_encrypt,
  autograph_subject,
  autograph_verify_data,
  autograph_verify_identity
} from './clib'

export const createDecrypt = (theirSecretKey: Uint8Array): DecryptFunction => {
  const messageIndex = new Uint8Array(8)
  const decryptIndex = new Uint8Array(8)
  const skippedKeys = new Uint8Array(40002)
  return (message: Uint8Array) => {
    const data = createPlaintextBytes(message.byteLength)
    const success = autograph_decrypt(
      data,
      messageIndex,
      decryptIndex,
      skippedKeys,
      theirSecretKey,
      message,
      BigInt(message.byteLength)
    )
    return { success, index: bytesToIndex(messageIndex), data }
  }
}

export const createEncrypt = (ourSecretKey: Uint8Array): EncryptFunction => {
  const messageIndex = new Uint8Array(8)
  return (data: Uint8Array) => {
    const message = createMessageBytes(data.byteLength)
    const success = autograph_encrypt(
      message,
      messageIndex,
      ourSecretKey,
      data,
      BigInt(data.byteLength)
    )
    return { success, index: bytesToIndex(messageIndex), message }
  }
}

export const createSignData =
  (sign: SignFunction, theirPublicKey: Uint8Array): SignDataFunction =>
  (data: Uint8Array) => {
    const subject = createSubjectBytes(data.byteLength)
    autograph_subject(subject, theirPublicKey, data, BigInt(data.byteLength))
    return sign(subject)
  }

export const createSignIdentity =
  (sign: SignFunction, theirPublicKey: Uint8Array): SignIdentityFunction =>
  () =>
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
  (certificates: Uint8Array) =>
    autograph_verify_identity(
      theirIdentityKey,
      certificates,
      countCertificates(certificates)
    )
