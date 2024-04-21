import {
  autograph_session_key_pair,
  autograph_identity_key_pair,
  autograph_get_public_key
} from './clib'
import { createKeyPair, createPublicKey } from './helpers'

export const generateIdentityKeyPair = (): Uint8Array => {
  const keyPair = createKeyPair()
  const success = autograph_identity_key_pair(keyPair)
  if (!success) {
    throw new Error('Key generation failed')
  }
  return keyPair
}

export const generateSessionKeyPair = (): Uint8Array => {
  const keyPair = createKeyPair()
  const success = autograph_session_key_pair(keyPair)
  if (!success) {
    throw new Error('Key generation failed')
  }
  return keyPair
}

export const getPublicKey = (keyPair: Uint8Array) => {
  const publicKey = createPublicKey()
  autograph_get_public_key(publicKey, keyPair)
  return publicKey
}
