import authenticate from './auth'
import { certify, verify } from './cert'
import {
  createTranscript,
  keyExchange,
  verifyKeyExchange
} from './key-exchange'
import { autograph_set_key_pairs, autograph_set_public_keys } from './clib'
import {
  createNonce,
  createSecretKey,
  createSkippedIndexes,
  decrypt,
  encrypt
} from './message'
import {
  createIdentityKeyPair,
  createIdentityPublicKey,
  createSessionKeyPair,
  createSessionPublicKey,
  getPublicKeys,
  getIdentityPublicKey,
  getSessionPublicKey
} from './key-pair'

export default class Channel {
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
    this.ourIdentityKeyPair = createIdentityKeyPair()
    this.ourSessionKeyPair = createSessionKeyPair()
    this.theirIdentityKey = createIdentityPublicKey()
    this.theirSessionKey = createSessionPublicKey()
    this.transcript = createTranscript()
    this.sendingKey = createSecretKey()
    this.receivingKey = createSecretKey()
    this.sendingNonce = createNonce()
    this.receivingNonce = createNonce()
    this.skippedIndexes = createSkippedIndexes()
  }

  setSkippedIndexes(count: number) {
    this.skippedIndexes = createSkippedIndexes(count)
  }

  setKeyPairs(ourIdentityKeyPair: Uint8Array, ourSessionKeyPair: Uint8Array) {
    autograph_set_key_pairs(
      this.ourIdentityKeyPair,
      this.ourSessionKeyPair,
      ourIdentityKeyPair,
      ourSessionKeyPair
    )
    return getPublicKeys(ourIdentityKeyPair, ourSessionKeyPair)
  }

  setOurKeyPairs(
    ourIdentityKeyPair: Uint8Array,
    ourSessionKeyPair: Uint8Array
  ) {
    return this.setKeyPairs(ourIdentityKeyPair, ourSessionKeyPair)
  }

  setPublicKeys(theirIdentityKey: Uint8Array, theirSessionKey: Uint8Array) {
    autograph_set_public_keys(
      this.theirIdentityKey,
      this.theirSessionKey,
      theirIdentityKey,
      theirSessionKey
    )
  }

  setTheirPublicKeys(
    theirIdentityKey: Uint8Array,
    theirSessionKey: Uint8Array
  ) {
    return this.setPublicKeys(theirIdentityKey, theirSessionKey)
  }

  getOurPublicKeys() {
    return getPublicKeys(this.ourIdentityKeyPair, this.ourSessionKeyPair)
  }

  getOurIdentityKey() {
    return getIdentityPublicKey(this.ourIdentityKeyPair)
  }

  getOurSessionKey() {
    return getSessionPublicKey(this.ourSessionKeyPair)
  }

  getTheirPublicKeys(): [Uint8Array, Uint8Array] {
    return [this.theirIdentityKey, this.theirSessionKey]
  }

  getTheirIdentityKey() {
    return this.theirIdentityKey
  }

  getTheirSessionKey() {
    return this.theirSessionKey
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
