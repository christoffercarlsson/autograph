import {
  NativeModulesProxy,
  EventEmitter,
  Subscription
} from 'expo-modules-core'

import ExpoAutographModule from './ExpoAutographModule'

const emitter = new EventEmitter(
  ExpoAutographModule ?? NativeModulesProxy.ExpoAutograph
)

export function addReadyListener(listener: () => void): Subscription {
  return emitter.addListener('onReady', listener)
}

export function authenticate(
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array
): Uint8Array {
  const { success, safetyNumber } = ExpoAutographModule.authenticate(
    ourIdentityKeyPair,
    theirIdentityKey
  )
  if (!success) {
    throw new Error('Authentication failed')
  }
  return safetyNumber
}

export function certify(
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  data?: Uint8Array
): Uint8Array {
  const { success, signature } = ExpoAutographModule.certify(
    ourIdentityKeyPair,
    theirIdentityKey,
    data
  )
  if (!success) {
    throw new Error('Certification failed')
  }
  return signature
}

export function verify(
  ownerIdentityKey: Uint8Array,
  certifierIdentityKey: Uint8Array,
  signature: Uint8Array,
  data?: Uint8Array
): boolean {
  return ExpoAutographModule.verify(
    ownerIdentityKey,
    certifierIdentityKey,
    signature,
    data
  )
}

export function keyExchange(
  isInitiator: boolean,
  ourIdentityKeyPair: Uint8Array,
  ourSessionKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSessionKey: Uint8Array
): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  const { success, transcript, ourSignature, sendingKey, receivingKey } =
    ExpoAutographModule.keyExchange(
      isInitiator,
      ourIdentityKeyPair,
      ourSessionKeyPair,
      theirIdentityKey,
      theirSessionKey
    )
  if (!success) {
    throw new Error('Key exchange failed')
  }
  return [transcript, ourSignature, sendingKey, receivingKey]
}

export function verifyKeyExchange(
  transcript: Uint8Array,
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  theirSignature: Uint8Array
) {
  const verified = ExpoAutographModule.verifyKeyExchange(
    transcript,
    ourIdentityKeyPair,
    theirIdentityKey,
    theirSignature
  )
  if (!verified) {
    throw new Error('Key exchange verification failed')
  }
}

export function generateIdentityKeyPair(): Uint8Array {
  const { success, keyPair } = ExpoAutographModule.generateIdentityKeyPair()
  if (!success) {
    throw new Error('Identity key pair generation failed')
  }
  return keyPair
}

export function generateSessionKeyPair(): Uint8Array {
  const { success, keyPair } = ExpoAutographModule.generateSessionKeyPair()
  if (!success) {
    throw new Error('Session key pair generation failed')
  }
  return keyPair
}

export function getIdentityPublicKey(keyPair: Uint8Array): Uint8Array {
  return ExpoAutographModule.getIdentityPublicKey(keyPair)
}

export function getSessionPublicKey(keyPair: Uint8Array): Uint8Array {
  return ExpoAutographModule.getSessionPublicKey(keyPair)
}

export function getPublicKeys(
  identityKeyPair: Uint8Array,
  sessionKeyPair: Uint8Array
): [Uint8Array, Uint8Array] {
  const { identityKey, sessionKey } = ExpoAutographModule.getPublicKeys(
    identityKeyPair,
    sessionKeyPair
  )
  return [identityKey, sessionKey]
}

export function createNonce(): Uint8Array {
  return ExpoAutographModule.createNonce()
}

export function createSkippedIndexes(count?: number): Uint8Array {
  return ExpoAutographModule.createSkippedIndexes(count || 0)
}

export function generateSecretKey(): Uint8Array {
  const { success, key } = ExpoAutographModule.generateSecretKey()
  if (!success) {
    throw new Error('Key generation failed')
  }
  return key
}

export function encrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array
): [number, Uint8Array] {
  const {
    success,
    nonce: n,
    index,
    ciphertext
  } = ExpoAutographModule.encrypt(key, nonce, plaintext)
  if (!success) {
    throw new Error('Encryption failed')
  }
  nonce.set(n)
  return [index, ciphertext]
}

export function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  skippedIndexes: Uint8Array,
  ciphertext: Uint8Array
): [number, Uint8Array] {
  const {
    success,
    nonce: n,
    skippedIndexes: indexes,
    index,
    plaintext
  } = ExpoAutographModule.decrypt(key, nonce, skippedIndexes, ciphertext)
  if (!success) {
    throw new Error('Decryption failed')
  }
  nonce.set(n)
  skippedIndexes.set(indexes)
  return [index, plaintext]
}

export class Channel {
  private ourIdentityKeyPair: Uint8Array
  private ourSessionKeyPair: Uint8Array
  private theirIdentityKey: Uint8Array
  private theirSessionKey: Uint8Array
  private transcript: Uint8Array
  private sendingKey: Uint8Array
  private receivingKey: Uint8Array
  private sendingNonce: Uint8Array
  private receivingNonce: Uint8Array
  private skippedIndexes: Uint8Array

  constructor() {
    this.ourIdentityKeyPair = new Uint8Array()
    this.ourSessionKeyPair = new Uint8Array()
    this.theirIdentityKey = new Uint8Array()
    this.theirSessionKey = new Uint8Array()
    this.transcript = new Uint8Array()
    this.sendingKey = new Uint8Array()
    this.receivingKey = new Uint8Array()
    this.sendingNonce = createNonce()
    this.receivingNonce = createNonce()
    this.skippedIndexes = createSkippedIndexes()
  }

  useKeyPairs(ourIdentityKeyPair: Uint8Array, ourSessionKeyPair: Uint8Array) {
    this.ourIdentityKeyPair = ourIdentityKeyPair
    this.ourSessionKeyPair = ourSessionKeyPair
    return getPublicKeys(ourIdentityKeyPair, ourSessionKeyPair)
  }

  usePublicKeys(theirIdentityKey: Uint8Array, theirSessionKey: Uint8Array) {
    this.theirIdentityKey = theirIdentityKey
    this.theirSessionKey = theirSessionKey
  }

  authenticate() {
    return authenticate(this.ourIdentityKeyPair, this.theirIdentityKey)
  }

  certify(data?: Uint8Array) {
    return certify(this.ourIdentityKeyPair, this.theirIdentityKey, data)
  }

  verify(
    certifierIdentityKey: Uint8Array,
    signature: Uint8Array,
    data?: Uint8Array
  ) {
    return verify(this.theirIdentityKey, certifierIdentityKey, signature, data)
  }

  keyExchange(isInitiator: boolean) {
    const [transcript, ourSignature, sendingKey, receivingKey] = keyExchange(
      isInitiator,
      this.ourIdentityKeyPair,
      this.ourSessionKeyPair,
      this.theirIdentityKey,
      this.theirSessionKey
    )
    this.transcript = transcript
    this.sendingKey = sendingKey
    this.receivingKey = receivingKey
    return ourSignature
  }

  verifyKeyExchange(theirSignature: Uint8Array) {
    verifyKeyExchange(
      this.transcript,
      this.ourIdentityKeyPair,
      this.theirIdentityKey,
      theirSignature
    )
  }

  encrypt(plaintext: Uint8Array) {
    return encrypt(this.sendingKey, this.sendingNonce, plaintext)
  }

  decrypt(ciphertext: Uint8Array) {
    return decrypt(
      this.receivingKey,
      this.receivingNonce,
      this.skippedIndexes,
      ciphertext
    )
  }
}
