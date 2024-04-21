import {
  createKeyPair,
  zeroize,
  createPublicKey,
  createTranscript,
  createSecretKey,
  createNonce
} from './helpers'
import authenticate from './auth'
import { certify, verify } from './cert'
import { keyExchange, verifyKeyExchange } from './key-exchange'
import { autograph_use_key_pairs, autograph_use_public_keys } from './clib'
import { decrypt, encrypt } from './message'

const SKIPPED_INDEXES_MAX_COUNT = 65535
const SKIPPED_INDEXES_DEFAULT_COUNT = 100

const createSkippedIndexes = (count?: number) =>
  new Uint32Array(
    count >= 0 && count <= SKIPPED_INDEXES_MAX_COUNT
      ? count
      : SKIPPED_INDEXES_DEFAULT_COUNT
  )

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
  private skippedIndexes: Uint32Array
  private established: boolean

  constructor(skippedIndexesCount?: number) {
    this.ourIdentityKeyPair = createKeyPair()
    this.ourSessionKeyPair = createKeyPair()
    this.theirIdentityKey = createPublicKey()
    this.theirSessionKey = createPublicKey()
    this.transcript = createTranscript()
    this.sendingKey = createSecretKey()
    this.receivingKey = createSecretKey()
    this.sendingNonce = createNonce()
    this.receivingNonce = createNonce()
    this.skippedIndexes = createSkippedIndexes(skippedIndexesCount)
    this.established = false
  }

  isEstablished() {
    return this.established
  }

  useKeyPairs(
    ourIdentityKeyPair: Uint8Array,
    ourSessionKeyPair: Uint8Array
  ): [Uint8Array, Uint8Array] {
    this.established = false
    const identityKey = createPublicKey()
    const sessionKey = createPublicKey()
    const ready = autograph_use_key_pairs(
      identityKey,
      sessionKey,
      this.ourIdentityKeyPair,
      this.ourSessionKeyPair,
      ourIdentityKeyPair,
      ourSessionKeyPair
    )
    if (!ready) {
      throw new Error('Initialization failed')
    }
    return [identityKey, sessionKey]
  }

  usePublicKeys(theirIdentityKey: Uint8Array, theirSessionKey: Uint8Array) {
    this.established = false
    autograph_use_public_keys(
      this.theirIdentityKey,
      this.theirSessionKey,
      theirIdentityKey,
      theirSessionKey
    )
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
    this.established = false
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
    this.established = true
    zeroize(this.sendingNonce)
    zeroize(this.receivingNonce)
    this.skippedIndexes = this.skippedIndexes.fill(0)
  }

  encrypt(plaintext: Uint8Array) {
    if (this.established) {
      return encrypt(this.sendingKey, this.sendingNonce, plaintext)
    } else {
      throw new Error('Encryption failed')
    }
  }

  decrypt(ciphertext: Uint8Array) {
    if (this.established) {
      return decrypt(
        this.receivingKey,
        this.receivingNonce,
        this.skippedIndexes,
        ciphertext
      )
    } else {
      throw new Error('Decryption failed')
    }
  }

  close() {
    this.established = false
    zeroize(this.ourIdentityKeyPair)
    zeroize(this.ourSessionKeyPair)
    zeroize(this.sendingKey)
    zeroize(this.receivingKey)
    zeroize(this.sendingNonce)
    zeroize(this.receivingNonce)
    this.skippedIndexes = this.skippedIndexes.fill(0)
  }
}
