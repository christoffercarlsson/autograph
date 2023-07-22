import {
  generateKeyPair as generateX25519KeyPair,
  generateSignKeyPair as generateEd25519KeyPair
} from 'stedy'
import { KeyPair, KeyPairResult } from '../types'
import createParty from './party'
import { exportKeyPair } from './utils'
import { alloc } from 'stedy/bytes'

const createKeyPairResult = async (
  success: boolean,
  keyPair?: KeyPair
): Promise<KeyPairResult> => {
  if (success) {
    return { success, keyPair: await exportKeyPair(keyPair) }
  }
  return { success, keyPair: { publicKey: alloc(32), privateKey: alloc(32) } }
}

const generateIdentityKeyPair = async (): Promise<KeyPairResult> => {
  try {
    const keyPair = await generateEd25519KeyPair()
    return createKeyPairResult(true, keyPair)
  } catch (error) {
    return createKeyPairResult(false)
  }
}

const generateEphemeralKeyPair = async (): Promise<KeyPairResult> => {
  try {
    const keyPair = await generateX25519KeyPair()
    return createKeyPairResult(true, keyPair)
  } catch (error) {
    return createKeyPairResult(false)
  }
}

const createInitiator = (identityKeyPair: KeyPair, ephemeralKeyPair: KeyPair) =>
  createParty(true, identityKeyPair, ephemeralKeyPair)

const createResponder = (identityKeyPair: KeyPair, ephemeralKeyPair: KeyPair) =>
  createParty(false, identityKeyPair, ephemeralKeyPair)

export {
  createInitiator,
  createResponder,
  generateIdentityKeyPair,
  generateEphemeralKeyPair
}
