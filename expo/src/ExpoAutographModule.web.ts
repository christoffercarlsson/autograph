import * as Autograph from 'autograph-protocol'
import { EventEmitter } from 'expo-modules-core'

const authenticate = (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array
): { success: boolean; safetyNumber: Uint8Array } => {
  try {
    const safetyNumber = Autograph.authenticate(
      ourIdentityKeyPair,
      theirIdentityKey
    )
    return { success: true, safetyNumber }
  } catch {
    return { success: false, safetyNumber: new Uint8Array() }
  }
}

const certify = (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  data?: Uint8Array
): { success: boolean; signature: Uint8Array } => {
  try {
    const signature = Autograph.certify(
      ourIdentityKeyPair,
      theirIdentityKey,
      data
    )
    return { success: true, signature }
  } catch {
    return { success: false, signature: new Uint8Array() }
  }
}

const verify = (
  ownerIdentityKey: Uint8Array,
  certifierIdentityKey: Uint8Array,
  signature: Uint8Array,
  data?: Uint8Array
): boolean => {
  try {
    const verified = Autograph.verify(
      ownerIdentityKey,
      certifierIdentityKey,
      signature,
      data
    )
    return verified
  } catch {
    return false
  }
}

const keyExchange = (
  isInitiator: boolean,
  ourIdentityKeyPair: Uint8Array,
  ourSessionKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSessionKey: Uint8Array
): {
  success: boolean
  transcript: Uint8Array
  ourSignature: Uint8Array
  sendingKey: Uint8Array
  receivingKey: Uint8Array
} => {
  try {
    const [transcript, ourSignature, sendingKey, receivingKey] =
      Autograph.keyExchange(
        isInitiator,
        ourIdentityKeyPair,
        ourSessionKeyPair,
        theirIdentityKey,
        theirSessionKey
      )
    return { success: true, transcript, ourSignature, sendingKey, receivingKey }
  } catch {
    return {
      success: false,
      transcript: new Uint8Array(),
      ourSignature: new Uint8Array(),
      sendingKey: new Uint8Array(),
      receivingKey: new Uint8Array()
    }
  }
}

const verifyKeyExchange = (
  transcript: Uint8Array,
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSignature: Uint8Array
): boolean => {
  try {
    Autograph.verifyKeyExchange(
      transcript,
      ourIdentityKeyPair,
      theirIdentityKey,
      theirSignature
    )
    return true
  } catch {
    return false
  }
}

const generateIdentityKeyPair = (): {
  success: boolean
  keyPair: Uint8Array
} => {
  try {
    const keyPair = Autograph.generateIdentityKeyPair()
    return { success: true, keyPair }
  } catch {
    return { success: false, keyPair: new Uint8Array() }
  }
}

const generateSessionKeyPair = (): {
  success: boolean
  keyPair: Uint8Array
} => {
  try {
    const keyPair = Autograph.generateSessionKeyPair()
    return { success: true, keyPair }
  } catch {
    return { success: false, keyPair: new Uint8Array() }
  }
}

const getIdentityPublicKey = (keyPair: Uint8Array): Uint8Array => {
  return Autograph.getIdentityPublicKey(keyPair)
}

const getSessionPublicKey = (keyPair: Uint8Array): Uint8Array => {
  return Autograph.getSessionPublicKey(keyPair)
}

const getPublicKeys = (
  identityKeyPair: Uint8Array,
  sessionKeyPair: Uint8Array
): { identityKey: Uint8Array; sessionKey: Uint8Array } => {
  const [identityKey, sessionKey] = Autograph.getPublicKeys(
    identityKeyPair,
    sessionKeyPair
  )
  return { identityKey, sessionKey }
}

const createNonce = () => Autograph.createNonce()

const createSkippedIndexes = (count?: number) =>
  Autograph.createSkippedIndexes(count || 0)

const generateSecretKey = (): { success: boolean; key: Uint8Array } => {
  try {
    const key = Autograph.generateSecretKey()
    return { success: true, key }
  } catch {
    return { success: false, key: new Uint8Array() }
  }
}

const encrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array
): {
  success: boolean
  nonce: Uint8Array
  index: number
  ciphertext: Uint8Array
} => {
  try {
    const [index, ciphertext] = Autograph.encrypt(key, nonce, plaintext)
    return { success: true, nonce, index, ciphertext }
  } catch {
    return {
      success: false,
      nonce: new Uint8Array(),
      index: 0,
      ciphertext: new Uint8Array()
    }
  }
}

const decrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  skippedIndexes: Uint8Array,
  ciphertext: Uint8Array
): {
  success: boolean
  nonce: Uint8Array
  skippedIndexes: Uint8Array
  index: number
  plaintext: Uint8Array
} => {
  try {
    const [index, plaintext] = Autograph.decrypt(
      key,
      nonce,
      skippedIndexes,
      ciphertext
    )
    return { success: true, nonce, skippedIndexes, index, plaintext }
  } catch {
    return {
      success: false,
      nonce: new Uint8Array(),
      skippedIndexes: new Uint8Array(),
      index: 0,
      plaintext: new Uint8Array()
    }
  }
}

const emitter = new EventEmitter({} as any)

Autograph.ready().then(() => {
  emitter.emit('onReady')
})

export default {
  authenticate,
  certify,
  verify,
  keyExchange,
  verifyKeyExchange,
  generateIdentityKeyPair,
  generateSessionKeyPair,
  getIdentityPublicKey,
  getSessionPublicKey,
  getPublicKeys,
  createNonce,
  createSkippedIndexes,
  generateSecretKey,
  encrypt,
  decrypt
}
