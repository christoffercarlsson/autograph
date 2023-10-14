import { autograph_ciphertext_size, autograph_plaintext_size } from './clib'

export const createHandshakeBytes = () => new Uint8Array(96)

export const createMessageBytes = (size: number) =>
  new Uint8Array(autograph_ciphertext_size(size))

export const createPlaintextBytes = (size: number) =>
  new Uint8Array(autograph_plaintext_size(size))

export const createPrivateKeyBytes = () => new Uint8Array(32)

export const createPublicKeyBytes = () => new Uint8Array(32)

export const createSafetyNumberBytes = () => new Uint8Array(60)

export const createSecretKeyBytes = () => new Uint8Array(32)

export const createSignatureBytes = () => new Uint8Array(64)

export const createSubjectBytes = (size: number) => new Uint8Array(size + 32)

export const createTranscriptBytes = () => new Uint8Array(128)
