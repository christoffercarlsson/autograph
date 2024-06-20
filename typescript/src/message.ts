import {
  autograph_ciphertext_size,
  autograph_decrypt,
  autograph_encrypt,
  autograph_generate_secret_key,
  autograph_nonce_size,
  autograph_plaintext_size,
  autograph_secret_key_size,
  autograph_skipped_indexes_size
} from './clib'

export const createSecretKey = () => new Uint8Array(autograph_secret_key_size())

export const generateSecretKey = () => {
  const key = createSecretKey()
  const success = autograph_generate_secret_key(key)
  if (!success) {
    throw new Error('Key generation failed')
  }
  return key
}

export const createNonce = () => new Uint8Array(autograph_nonce_size())

export const createSkippedIndexes = (count?: number) =>
  new Uint8Array(
    autograph_skipped_indexes_size(count > 0 && count <= 65535 ? count : 0)
  )

const createCiphertext = (plaintext: Uint8Array) => {
  const size = autograph_ciphertext_size(plaintext.byteLength)
  return new Uint8Array(size)
}

const createPlaintext = (ciphertext: Uint8Array) => {
  const size = autograph_plaintext_size(ciphertext.byteLength)
  return new Uint8Array(size)
}

export const encrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array
): [number, Uint8Array] => {
  const ciphertext = createCiphertext(plaintext)
  const index = new Uint32Array([0])
  const success = autograph_encrypt(
    index,
    ciphertext,
    key,
    nonce,
    plaintext,
    plaintext.length
  )
  if (!success) {
    throw new Error('Encryption failed')
  }
  return [index.at(0), ciphertext]
}

export const decrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  skippedIndexes: Uint8Array,
  ciphertext: Uint8Array
): [number, Uint8Array] => {
  const plaintext = createPlaintext(ciphertext)
  const index = new Uint32Array([0])
  const plaintextSize = new Uint32Array([0])
  const success = autograph_decrypt(
    index,
    plaintext,
    plaintextSize,
    key,
    nonce,
    skippedIndexes,
    skippedIndexes.length,
    ciphertext,
    ciphertext.length
  )
  if (!success) {
    throw new Error('Decryption failed')
  }
  return [index.at(0), plaintext.subarray(0, plaintextSize.at(0))]
}
