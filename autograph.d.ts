export declare const authenticate: (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array
) => Uint8Array

export declare const certify: (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  data?: Uint8Array
) => Uint8Array

export declare const verify: (
  ownerIdentityKey: Uint8Array,
  certifierIdentityKey: Uint8Array,
  signature: Uint8Array,
  data?: Uint8Array
) => boolean

export default class Channel {
  constructor(skippedIndexesCount?: number)

  isEstablished(): boolean

  useKeyPairs(
    ourIdentityKeyPair: Uint8Array,
    ourSessionKeyPair: Uint8Array
  ): [Uint8Array, Uint8Array]

  usePublicKeys(theirIdentityKey: Uint8Array, theirSessionKey: Uint8Array): void

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

  close(): void
}

export declare const ready: () => Promise<void>

export declare const zeroize: (data: Uint8Array) => void

export declare const isZero: (data: Uint8Array) => boolean

export declare const keyExchange: (
  isInitiator: boolean,
  ourIdentityKeyPair: Uint8Array,
  ourSessionKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSessionKey: Uint8Array
) => [Uint8Array, Uint8Array, Uint8Array, Uint8Array]

export declare const verifyKeyExchange: (
  transcript: Uint8Array,
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSignature: Uint8Array
) => void

export declare const generateIdentityKeyPair: () => Uint8Array

export declare const generateSessionKeyPair: () => Uint8Array

export declare const getPublicKey: (keyPair: Uint8Array) => Uint8Array

export declare const encrypt: (
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array
) => [number, Uint8Array]

export declare const decrypt: (
  key: Uint8Array,
  nonce: Uint8Array,
  skippedIndexes: Uint32Array,
  ciphertext: Uint8Array
) => [number, Uint8Array]
