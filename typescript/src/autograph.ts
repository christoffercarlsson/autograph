import {
  generateKeyPair as generateX25519KeyPair,
  generateSignKeyPair as generateEd25519KeyPair
} from 'stedy'
import { alloc } from 'stedy/bytes'
import { KeyPair, KeyPairResult, SignFunction } from '../types'
import createParty from './party'
import { createErrorSignResult, ensureSignResult, exportKeyPair } from './utils'
import { sign } from './crypto/sign'

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

const createSign =
  (identityPrivateKey: BufferSource): SignFunction =>
  async (subject: BufferSource) => {
    try {
      const signature = await sign(identityPrivateKey, subject)
      return ensureSignResult({ success: true, signature })
    } catch (error) {
      return createErrorSignResult()
    }
  }

const ensureParty = (
  isInitiator: boolean,
  a: KeyPair | SignFunction,
  b?: BufferSource
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

const createInitiator = (a: KeyPair | SignFunction, b?: BufferSource) =>
  ensureParty(true, a, b)

const createResponder = (a: KeyPair | SignFunction, b?: BufferSource) =>
  ensureParty(false, a, b)

export {
  createInitiator,
  createResponder,
  createSign,
  generateIdentityKeyPair,
  generateEphemeralKeyPair
}
