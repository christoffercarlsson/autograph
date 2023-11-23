import { SignFunction, KeyPair } from '../../types'
import {
  PUBLIC_KEY_SIZE,
  SIGNATURE_SIZE,
  createCiphertextBytes,
  createHandshakeBytes,
  createIndexBytes,
  createPlaintextBytes,
  createSecretKeyBytes,
  createSizeBytes,
  createSkippedKeysBytes,
  createSubjectBytes,
  createTranscriptBytes
} from './utils'
import {
  autograph_decrypt,
  autograph_encrypt,
  autograph_init,
  autograph_key_exchange_signature,
  autograph_key_exchange_transcript,
  autograph_key_exchange_verify,
  autograph_read_uint32,
  autograph_read_uint64,
  autograph_subject,
  autograph_verify_data,
  autograph_verify_identity
} from './clib'
import {
  ChannelUnestablishedError,
  DecryptionError,
  EncryptionError,
  InitializationError,
  KeyExchangeError,
  KeyExchangeVerificationError
} from './error'
import calculateSafetyNumber from './safety-number'

class DecryptionState {
  public decryptIndex: Uint8Array
  public messageIndex: Uint8Array
  public plaintextSize: Uint8Array
  public secretKey: Uint8Array
  public skippedKeys: Uint8Array

  constructor(secretKey: Uint8Array) {
    this.decryptIndex = createIndexBytes()
    this.messageIndex = createIndexBytes()
    this.plaintextSize = createSizeBytes()
    this.secretKey = secretKey
    this.skippedKeys = createSkippedKeysBytes()
  }

  readMessageIndex(): bigint {
    return autograph_read_uint64(this.messageIndex)
  }

  private readPlaintextSize(): number {
    return autograph_read_uint32(this.plaintextSize)
  }

  resizeData(plaintext: Uint8Array) {
    return plaintext.subarray(0, this.readPlaintextSize())
  }
}

class EncryptionState {
  public messageIndex: Uint8Array
  public secretKey: Uint8Array

  constructor(secretKey: Uint8Array) {
    this.messageIndex = createIndexBytes()
    this.secretKey = secretKey
  }

  readMessageIndex(): bigint {
    return autograph_read_uint64(this.messageIndex)
  }
}

const countCertificates = (certificates: Uint8Array) =>
  certificates.byteLength / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)

export default class Channel {
  private decryptState: DecryptionState = null
  private encryptState: EncryptionState = null
  private ourIdentityKey: Uint8Array = null
  private sign: SignFunction
  private theirPublicKey: Uint8Array = null
  private transcript: Uint8Array = null
  private verified = false

  constructor(sign: SignFunction, ourIdentityKey: Uint8Array) {
    this.ourIdentityKey = ourIdentityKey
    this.sign = sign
  }

  calculateSafetyNumber() {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    return calculateSafetyNumber(this.ourIdentityKey, this.theirPublicKey)
  }

  close() {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    this.decryptState = null
    this.encryptState = null
    this.theirPublicKey = null
    this.transcript = null
    this.verified = false
  }

  static async create(sign: SignFunction, ourIdentityKey: Uint8Array) {
    if ((await autograph_init()) < 0) {
      throw new InitializationError()
    }
    return Reflect.construct(this, [sign, ourIdentityKey])
  }

  decrypt(message: Uint8Array): [bigint, Uint8Array] {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    const plaintext = createPlaintextBytes(message.byteLength)
    const success =
      autograph_decrypt(
        plaintext,
        this.decryptState.plaintextSize,
        this.decryptState.messageIndex,
        this.decryptState.decryptIndex,
        this.decryptState.skippedKeys,
        this.decryptState.secretKey,
        message,
        message.byteLength
      ) === 0
    if (!success) {
      throw new DecryptionError()
    }
    return [
      this.decryptState.readMessageIndex(),
      this.decryptState.resizeData(plaintext)
    ]
  }

  encrypt(plaintext: Uint8Array): [bigint, Uint8Array] {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    const ciphertext = createCiphertextBytes(plaintext.byteLength)
    const success =
      autograph_encrypt(
        ciphertext,
        this.encryptState.messageIndex,
        this.encryptState.secretKey,
        plaintext,
        plaintext.byteLength
      ) === 0
    if (!success) {
      throw new EncryptionError()
    }
    return [this.encryptState.readMessageIndex(), ciphertext]
  }

  isClosed() {
    return !(this.isEstablished() || this.isInitialized())
  }

  isEstablished() {
    return (
      this.theirPublicKey !== null &&
      this.decryptState !== null &&
      this.encryptState !== null &&
      this.transcript === null &&
      this.verified
    )
  }

  isInitialized() {
    return (
      this.theirPublicKey !== null &&
      this.decryptState !== null &&
      this.encryptState !== null &&
      this.transcript !== null &&
      !this.verified
    )
  }

  async performKeyExchange(
    isInitiator: boolean,
    ourEphemeralKeyPair: KeyPair,
    theirIdentityKey: Uint8Array,
    theirEphemeralKey: Uint8Array
  ) {
    const handshake = createHandshakeBytes()
    const transcript = createTranscriptBytes()
    const ourSecretKey = createSecretKeyBytes()
    const theirSecretKey = createSecretKeyBytes()
    const transcriptSuccess =
      autograph_key_exchange_transcript(
        transcript,
        isInitiator ? 1 : 0,
        this.ourIdentityKey,
        ourEphemeralKeyPair.publicKey,
        theirIdentityKey,
        theirEphemeralKey
      ) === 0
    if (!transcriptSuccess) {
      throw new KeyExchangeError()
    }
    const signature = await this.sign(transcript)
    const keyExchangeSuccess =
      autograph_key_exchange_signature(
        handshake,
        ourSecretKey,
        theirSecretKey,
        isInitiator ? 1 : 0,
        signature,
        ourEphemeralKeyPair.privateKey,
        theirEphemeralKey
      ) === 0
    if (!keyExchangeSuccess) {
      throw new KeyExchangeError()
    }
    this.decryptState = new DecryptionState(theirSecretKey)
    this.encryptState = new EncryptionState(ourSecretKey)
    this.theirPublicKey = theirIdentityKey
    this.transcript = transcript
    this.verified = false
    return handshake
  }

  signData(data: Uint8Array) {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    const subject = createSubjectBytes(data.byteLength)
    autograph_subject(subject, this.theirPublicKey, data, data.byteLength)
    return this.sign(subject)
  }

  signIdentity() {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    return this.sign(this.theirPublicKey)
  }

  verifyData(certificates: Uint8Array, data: Uint8Array) {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    return (
      autograph_verify_data(
        this.theirPublicKey,
        certificates,
        countCertificates(certificates),
        data,
        data.byteLength
      ) === 0
    )
  }

  verifyIdentity(certificates: Uint8Array) {
    if (!this.isEstablished()) {
      throw new ChannelUnestablishedError()
    }
    return (
      autograph_verify_identity(
        this.theirPublicKey,
        certificates,
        countCertificates(certificates)
      ) === 0
    )
  }

  verifyKeyExchange(theirHandshake: Uint8Array) {
    this.verified =
      autograph_key_exchange_verify(
        this.transcript,
        this.theirPublicKey,
        this.decryptState.secretKey,
        theirHandshake
      ) === 0
    this.transcript = null
    if (!this.verified) {
      throw new KeyExchangeVerificationError()
    }
  }
}
