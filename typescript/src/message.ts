import {
  autograph_ciphertext_size,
  autograph_decrypt,
  autograph_encrypt,
  autograph_plaintext_size
} from './clib'

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
  skippedIndexes: Uint32Array,
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
