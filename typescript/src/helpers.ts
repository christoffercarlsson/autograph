import {
  autograph_key_pair_size,
  autograph_nonce_size,
  autograph_public_key_size,
  autograph_secret_key_size,
  autograph_signature_size,
  autograph_transcript_size,
  autograph_zeroize,
  autograph_is_zero
} from './clib'

export const createKeyPair = () => new Uint8Array(autograph_key_pair_size())

export const createNonce = () => new Uint8Array(autograph_nonce_size())

export const createPublicKey = () => new Uint8Array(autograph_public_key_size())

export const createSignature = () => new Uint8Array(autograph_signature_size())

export const createSecretKey = () => new Uint8Array(autograph_secret_key_size())

export const createTranscript = () =>
  new Uint8Array(autograph_transcript_size())

export const zeroize = (data: Uint8Array) => {
  autograph_zeroize(data, data.length)
}

export const isZero = (data: Uint8Array) => autograph_is_zero(data, data.length)
