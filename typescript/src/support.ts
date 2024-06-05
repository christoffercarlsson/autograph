import {
  autograph_key_pair_size,
  autograph_nonce_size,
  autograph_public_key_size,
  autograph_safety_number_size,
  autograph_secret_key_size,
  autograph_signature_size,
  autograph_skipped_indexes_count,
  autograph_transcript_size
} from './clib'

export const createKeyPair = () => new Uint8Array(autograph_key_pair_size())

export const createNonce = () => new Uint8Array(autograph_nonce_size())

export const createPublicKey = () => new Uint8Array(autograph_public_key_size())

export const createSafetyNumber = () =>
  new Uint8Array(autograph_safety_number_size())

export const createSecretKey = () => new Uint8Array(autograph_secret_key_size())

export const createSignature = () => new Uint8Array(autograph_signature_size())

export const createTranscript = () =>
  new Uint8Array(autograph_transcript_size())

export const createSkippedIndexes = () =>
  new Uint32Array(autograph_skipped_indexes_count())
