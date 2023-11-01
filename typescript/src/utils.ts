import {
  autograph_ciphertext_size,
  autograph_plaintext_size,
  autograph_subject_size
} from './clib'

export const HANDSHAKE_SIZE = 96
export const INDEX_SIZE = 8
export const PRIVATE_KEY_SIZE = 32
export const PUBLIC_KEY_SIZE = 32
export const SAFETY_NUMBER_SIZE = 60
export const SECRET_KEY_SIZE = 32
export const SIGNATURE_SIZE = 64
export const SIZE_SIZE = 4
export const SKIPPED_KEYS_SIZE = 40002
export const TRANSCRIPT_SIZE = 128

export const createCiphertextBytes = (size: number) =>
  new Uint8Array(autograph_ciphertext_size(size))

export const createHandshakeBytes = () => new Uint8Array(HANDSHAKE_SIZE)

export const createIndexBytes = () => new Uint8Array(INDEX_SIZE)

export const createPlaintextBytes = (size: number) =>
  new Uint8Array(autograph_plaintext_size(size))

export const createPrivateKeyBytes = () => new Uint8Array(PRIVATE_KEY_SIZE)

export const createPublicKeyBytes = () => new Uint8Array(PUBLIC_KEY_SIZE)

export const createSafetyNumberBytes = () => new Uint8Array(SAFETY_NUMBER_SIZE)

export const createSecretKeyBytes = () => new Uint8Array(SECRET_KEY_SIZE)

export const createSignatureBytes = () => new Uint8Array(SIGNATURE_SIZE)

export const createSizeBytes = () => new Uint8Array(SIZE_SIZE)

export const createSkippedKeysBytes = () => new Uint8Array(SKIPPED_KEYS_SIZE)

export const createSubjectBytes = (size: number) =>
  new Uint8Array(autograph_subject_size(size))

export const createTranscriptBytes = () => new Uint8Array(TRANSCRIPT_SIZE)
