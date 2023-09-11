import {
  autograph_decrypt,
  autograph_encrypt,
  autograph_init,
  autograph_key_exchange,
  autograph_key_exchange_signature,
  autograph_key_exchange_transcript,
  autograph_key_exchange_verify,
  autograph_key_pair_ephemeral,
  autograph_key_pair_identity,
  autograph_safety_number,
  autograph_sign_data,
  autograph_sign_identity,
  autograph_sign_subject,
  autograph_subject,
  autograph_verify_data,
  autograph_verify_identity
} from './clib'
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
  autograph_decrypt,
  autograph_encrypt,
  autograph_init,
  autograph_key_exchange,
  autograph_key_exchange_signature,
  autograph_key_exchange_transcript,
  autograph_key_exchange_verify,
  autograph_key_pair_ephemeral,
  autograph_key_pair_identity,
  autograph_safety_number,
  autograph_sign_data,
  autograph_sign_identity,
  autograph_sign_subject,
  autograph_subject,
  autograph_verify_data,
  autograph_verify_identity,
  createInitiator,
  createResponder,
  createSign,
  generateIdentityKeyPair,
  generateEphemeralKeyPair,
  autograph_init as init
}
