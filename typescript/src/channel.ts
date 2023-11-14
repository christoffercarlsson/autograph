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
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE,
  createCiphertextBytes,
  createIndexBytes,
  createPlaintextBytes,
  createSizeBytes,
  createSkippedKeysBytes,
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
import { DecryptionError, EncryptionError } from './error'

export const createDecrypt = (theirSecretKey: Uint8Array): DecryptFunction => {
  const messageIndex = createIndexBytes()
  const decryptIndex = createIndexBytes()
  const plaintextSize = createSizeBytes()
  const skippedKeys = createSkippedKeysBytes()
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
    if (!success) {
      throw new DecryptionError()
    }
    return [
      autograph_read_uint64(messageIndex),
      plaintext.subarray(0, autograph_read_uint32(plaintextSize))
    ]
  }
}

export const createEncrypt = (ourSecretKey: Uint8Array): EncryptFunction => {
  const messageIndex = createIndexBytes()
  return (plaintext: Uint8Array) => {
    const ciphertext = createCiphertextBytes(plaintext.byteLength)
    const success = autograph_encrypt(
      ciphertext,
      messageIndex,
      ourSecretKey,
      plaintext,
      plaintext.byteLength
    )
    if (!success) {
      throw new EncryptionError()
    }
    return [autograph_read_uint64(messageIndex), ciphertext]
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
  certificates.byteLength / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)

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
