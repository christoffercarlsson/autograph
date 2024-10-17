import {
  autograph_session_key_pair,
  autograph_session_key_pair_size,
  autograph_identity_key_pair,
  autograph_identity_key_pair_size,
  autograph_get_identity_public_key,
  autograph_get_session_public_key,
  autograph_identity_public_key_size,
  autograph_session_public_key_size
} from './clib'

export const createIdentityKeyPair = () =>
  new Uint8Array(autograph_identity_key_pair_size())

export const createSessionKeyPair = () =>
  new Uint8Array(autograph_session_key_pair_size())

export const createIdentityPublicKey = () =>
  new Uint8Array(autograph_identity_public_key_size())

export const createSessionPublicKey = () =>
  new Uint8Array(autograph_session_public_key_size())

export const generateIdentityKeyPair = (): Uint8Array => {
  const keyPair = createIdentityKeyPair()
  const success = autograph_identity_key_pair(keyPair)
  if (!success) {
    throw new Error('Identity key pair generation failed')
  }
  return keyPair
}

export const generateSessionKeyPair = (): Uint8Array => {
  const keyPair = createSessionKeyPair()
  const success = autograph_session_key_pair(keyPair)
  if (!success) {
    throw new Error('Session key pair generation failed')
  }
  return keyPair
}

export const getIdentityPublicKey = (keyPair: Uint8Array) => {
  const publicKey = createIdentityPublicKey()
  autograph_get_identity_public_key(publicKey, keyPair)
  return publicKey
}

export const getSessionPublicKey = (keyPair: Uint8Array) => {
  const publicKey = createSessionPublicKey()
  autograph_get_session_public_key(publicKey, keyPair)
  return publicKey
}

export const getPublicKeys = (
  identityKeyPair: Uint8Array,
  sessionKeyPair: Uint8Array
): [Uint8Array, Uint8Array] => {
  const identityKey = getIdentityPublicKey(identityKeyPair)
  const sessionKey = getSessionPublicKey(sessionKeyPair)
  return [identityKey, sessionKey]
}
