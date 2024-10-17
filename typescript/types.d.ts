declare const authenticate: (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array
) => Uint8Array

declare const certify: (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  data?: Uint8Array
) => Uint8Array

declare const verify: (
  ownerIdentityKey: Uint8Array,
  certifierIdentityKey: Uint8Array,
  signature: Uint8Array,
  data?: Uint8Array
) => boolean

declare class Channel {
  constructor(
    ourIdentityKeyPair: Uint8Array,
    ourSessionKeyPair: Uint8Array,
    theirIdentityKey: Uint8Array,
    theirSessionKey: Uint8Array
  )

  authenticate(): Uint8Array

  certify(data?: Uint8Array): Uint8Array

  verify(
    certifierIdentityKey: Uint8Array,
    signature: Uint8Array,
    data?: Uint8Array
  ): boolean

  keyExchange(isInitiator: boolean): Uint8Array

  verifyKeyExchange(theirSignature: Uint8Array): void

  encrypt(plaintext: Uint8Array): [number, Uint8Array]

  decrypt(ciphertext: Uint8Array): [number, Uint8Array]
}

declare const ready: () => Promise<void>

declare const keyExchange: (
  isInitiator: boolean,
  ourIdentityKeyPair: Uint8Array,
  ourSessionKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSessionKey: Uint8Array
) => [Uint8Array, Uint8Array, Uint8Array, Uint8Array]

declare const verifyKeyExchange: (
  transcript: Uint8Array,
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSignature: Uint8Array
) => void

declare const generateIdentityKeyPair: () => Uint8Array

declare const generateSessionKeyPair: () => Uint8Array

declare const getIdentityPublicKey: (keyPair: Uint8Array) => Uint8Array

declare const getSessionPublicKey: (keyPair: Uint8Array) => Uint8Array

declare const getPublicKeys: (
  identityKeyPair: Uint8Array,
  sessionKeyPair: Uint8Array
) => [Uint8Array, Uint8Array]

declare const createNonce: () => Uint8Array

declare const createSkippedIndexes: (count?: number) => Uint8Array

declare const generateSecretKey: () => Uint8Array

declare const encrypt: (
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array
) => [number, Uint8Array]

declare const decrypt: (
  key: Uint8Array,
  nonce: Uint8Array,
  skippedIndexes: Uint8Array,
  ciphertext: Uint8Array
) => [number, Uint8Array]

export {
  authenticate,
  certify,
  verify,
  Channel,
  ready,
  keyExchange,
  verifyKeyExchange,
  generateIdentityKeyPair,
  generateSessionKeyPair,
  getIdentityPublicKey,
  getSessionPublicKey,
  getPublicKeys,
  createNonce,
  createSkippedIndexes,
  generateSecretKey,
  encrypt,
  decrypt
}
