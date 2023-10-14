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
  createMessageBytes,
  createPlaintextBytes,
  createSubjectBytes
} from './utils'
import {
  autograph_decrypt,
  autograph_encrypt,
  autograph_read_uint32,
  autograph_read_uint64,
  autograph_subject,
  autograph_verify_data,
  autograph_verify_identity
} from './clib'

export const createDecrypt = (theirSecretKey: Uint8Array): DecryptFunction => {
  const messageIndex = new Uint8Array(8)
  const decryptIndex = new Uint8Array(8)
  const plaintextSize = new Uint8Array(4)
  const skippedKeys = new Uint8Array(40002)
  return (message: Uint8Array) => {
    const plaintext = createPlaintextBytes(message.byteLength)
    const success = autograph_decrypt(
      plaintext,
      plaintextSize,
      messageIndex,
      decryptIndex,
      skippedKeys,
      theirSecretKey,
      message,
      message.byteLength
    )
    return {
      success,
      index: autograph_read_uint64(messageIndex),
      data: plaintext.subarray(0, autograph_read_uint32(plaintextSize))
    }
  }
}

export const createEncrypt = (ourSecretKey: Uint8Array): EncryptFunction => {
  const messageIndex = new Uint8Array(8)
  return (plaintext: Uint8Array) => {
    const message = createMessageBytes(plaintext.byteLength)
    const success = autograph_encrypt(
      message,
      messageIndex,
      ourSecretKey,
      plaintext,
      plaintext.byteLength
    )
    return {
      success,
      index: autograph_read_uint64(messageIndex),
      message
    }
  }
}

export const createSignData =
  (sign: SignFunction, theirPublicKey: Uint8Array): SignDataFunction =>
  (data: Uint8Array) => {
    const subject = createSubjectBytes(data.byteLength)
    autograph_subject(subject, theirPublicKey, data, data.byteLength)
    return sign(subject)
  }

export const createSignIdentity =
  (sign: SignFunction, theirPublicKey: Uint8Array): SignIdentityFunction =>
  () =>
    sign(theirPublicKey)

const countCertificates = (certificates: Uint8Array) =>
  certificates.byteLength / 96

export const createVerifyData =
  (theirIdentityKey: Uint8Array): VerifyDataFunction =>
  (certificates: Uint8Array, data: Uint8Array) =>
    autograph_verify_data(
      theirIdentityKey,
      certificates,
      countCertificates(certificates),
      data,
      data.byteLength
    )

export const createVerifyIdentity =
  (theirIdentityKey: Uint8Array): VerifyIdentityFunction =>
  (certificates: Uint8Array) =>
    autograph_verify_identity(
      theirIdentityKey,
      certificates,
      countCertificates(certificates)
    )
