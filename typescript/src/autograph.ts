import { autograph_init as init } from './clib'
import { generateIdentityKeyPair, generateEphemeralKeyPair } from './key-pair'
import createParty from './party'
import { createSign } from './sign'
import { KeyPair, SignFunction } from '../types'

const ensureParty = (
  isInitiator: boolean,
  a: KeyPair | SignFunction,
  b?: Uint8Array
) => {
  const keyPair = a as KeyPair
  if (ArrayBuffer.isView(keyPair.privateKey)) {
    return createParty(
      isInitiator,
      createSign(keyPair.privateKey),
      keyPair.publicKey
    )
  }
  return createParty(isInitiator, a as SignFunction, b)
}

const createInitiator = (a: KeyPair | SignFunction, b?: Uint8Array) =>
  ensureParty(true, a, b)

const createResponder = (a: KeyPair | SignFunction, b?: Uint8Array) =>
  ensureParty(false, a, b)

export {
  createInitiator,
  createResponder,
  createSign,
  generateIdentityKeyPair,
  generateEphemeralKeyPair,
  init
}
