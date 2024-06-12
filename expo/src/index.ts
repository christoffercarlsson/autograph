import { createFrom, ENCODING_BASE64_URLSAFE } from 'stedy'

import ExpoAutographModule from './ExpoAutographModule'

function ensureBytes(data: Uint8Array | string | undefined): Uint8Array {
  return createFrom(data, ENCODING_BASE64_URLSAFE)
}

export function authenticate(
  ourIdentityKeyPair: Uint8Array | string,
  theirIdentityKey: Uint8Array | string
): Uint8Array {
  const [success, safetyNumber] = ExpoAutographModule.authenticate(
    ensureBytes(ourIdentityKeyPair),
    ensureBytes(theirIdentityKey)
  )
  if (!success) {
    throw new Error('Authentication failed')
  }
  return safetyNumber
}

export function certify(
  ourIdentityKeyPair: Uint8Array | string,
  theirIdentityKey: Uint8Array | string,
  data?: Uint8Array | string
): Uint8Array {
  const [success, signature] = ExpoAutographModule.certify(
    ensureBytes(ourIdentityKeyPair),
    ensureBytes(theirIdentityKey),
    ensureBytes(data)
  )
  if (!success) {
    throw new Error('Certification failed')
  }
  return signature
}

export function verify(
  ownerIdentityKey: Uint8Array | string,
  certifierIdentityKey: Uint8Array | string,
  signature: Uint8Array | string,
  data?: Uint8Array | string
): boolean {
  return ExpoAutographModule.verify(
    ensureBytes(ownerIdentityKey),
    ensureBytes(certifierIdentityKey),
    ensureBytes(signature),
    ensureBytes(data)
  )
}

export async function ready(): Promise<void> {
  const initialized = await ExpoAutographModule.ready()
  if (!initialized) {
    throw new Error('Initialization failed')
  }
}

export function keyExchange(
  isInitiator: boolean,
  ourIdentityKeyPair: Uint8Array | string,
  ourSessionKeyPair: Uint8Array | string,
  theirIdentityKey: Uint8Array | string,
  theirSessionKey: Uint8Array | string
): [Uint8Array, Uint8Array, Uint8Array, Uint8Array] {
  const [success, transcript, ourSignature, sendingKey, receivingKey] =
    ExpoAutographModule.keyExchange(
      isInitiator,
      ensureBytes(ourIdentityKeyPair),
      ensureBytes(ourSessionKeyPair),
      ensureBytes(theirIdentityKey),
      ensureBytes(theirSessionKey)
    )
  if (!success) {
    throw new Error('Key exchange failed')
  }
  return [transcript, ourSignature, sendingKey, receivingKey]
}

export function verifyKeyExchange(
  transcript: Uint8Array | string,
  ourIdentityKeyPair: Uint8Array | string,
  theirIdentityKey: Uint8Array | string,
  theirSignature: Uint8Array | string
) {
  const verified = ExpoAutographModule.verifyKeyExchange(
    ensureBytes(transcript),
    ensureBytes(ourIdentityKeyPair),
    ensureBytes(theirIdentityKey),
    ensureBytes(theirSignature)
  )
  if (!verified) {
    throw new Error('Key exchange verification failed')
  }
}

export function generateIdentityKeyPair(): Uint8Array {
  const [success, keyPair] = ExpoAutographModule.generateIdentityKeyPair()
  if (!success) {
    throw new Error('Identity key pair generation failed')
  }
  return keyPair
}

export function generateSessionKeyPair(): Uint8Array {
  const [success, keyPair] = ExpoAutographModule.generateSessionKeyPair()
  if (!success) {
    throw new Error('Session key pair generation failed')
  }
  return keyPair
}

export function getIdentityPublicKey(keyPair: Uint8Array | string): Uint8Array {
  return ExpoAutographModule.getIdentityPublicKey(ensureBytes(keyPair))
}

export function getSessionPublicKey(keyPair: Uint8Array | string): Uint8Array {
  return ExpoAutographModule.getSessionPublicKey(ensureBytes(keyPair))
}

export function getPublicKeys(
  identityKeyPair: Uint8Array | string,
  sessionKeyPair: Uint8Array | string
): [Uint8Array, Uint8Array] {
  const [identityKey, sessionKey] = ExpoAutographModule.getPublicKeys(
    ensureBytes(identityKeyPair),
    ensureBytes(sessionKeyPair)
  )
  return [identityKey, sessionKey]
}

export function createNonce(): Uint8Array {
  return ExpoAutographModule.createNonce()
}

export function createIndexes(count?: number): Uint32Array {
  return new Uint32Array(count && count > 0 && count <= 65535 ? count : 128)
}

export function generateSecretKey(): Uint8Array {
  const [success, key] = ExpoAutographModule.generateSecretKey()
  if (!success) {
    throw new Error('Key generation failed')
  }
  return key
}

export function encrypt(
  key: Uint8Array | string,
  nonce: Uint8Array | string,
  plaintext: Uint8Array | string
): [number, Uint8Array] {
  const [success, index, ciphertext] = ExpoAutographModule.encrypt(
    ensureBytes(key),
    ensureBytes(nonce),
    ensureBytes(plaintext)
  )
  if (!success) {
    throw new Error('Encryption failed')
  }
  return [index, ciphertext]
}

export function decrypt(
  key: Uint8Array | string,
  nonce: Uint8Array | string,
  skippedIndexes: Uint32Array,
  ciphertext: Uint8Array | string
): [number, Uint8Array] {
  const [success, index, plaintext] = ExpoAutographModule.decrypt(
    ensureBytes(key),
    ensureBytes(nonce),
    new Uint8Array(skippedIndexes.buffer),
    ensureBytes(ciphertext)
  )
  if (!success) {
    throw new Error('Decryption failed')
  }
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
  private skippedIndexes: Uint32Array

  constructor(
    ourIdentityKeyPair: Uint8Array | string,
    ourSessionKeyPair: Uint8Array | string,
    theirIdentityKey: Uint8Array | string,
    theirSessionKey: Uint8Array | string
  ) {
    this.ourIdentityKeyPair = ensureBytes(ourIdentityKeyPair)
    this.ourSessionKeyPair = ensureBytes(ourSessionKeyPair)
    this.theirIdentityKey = ensureBytes(theirIdentityKey)
    this.theirSessionKey = ensureBytes(theirSessionKey)
    this.transcript = new Uint8Array(64)
    this.sendingKey = new Uint8Array(32)
    this.receivingKey = new Uint8Array(32)
    this.sendingNonce = createNonce()
    this.receivingNonce = createNonce()
    this.skippedIndexes = createIndexes()
  }

  authenticate() {
    return authenticate(this.ourIdentityKeyPair, this.theirIdentityKey)
  }

  certify(data?: Uint8Array | string) {
    return certify(this.ourIdentityKeyPair, this.theirIdentityKey, data)
  }

  verify(
    certifierIdentityKey: Uint8Array | string,
    signature: Uint8Array | string,
    data?: Uint8Array | string
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

  verifyKeyExchange(theirSignature: Uint8Array | string) {
    verifyKeyExchange(
      this.transcript,
      this.ourIdentityKeyPair,
      this.theirIdentityKey,
      theirSignature
    )
  }

  encrypt(plaintext: Uint8Array | string) {
    return encrypt(this.sendingKey, this.sendingNonce, plaintext)
  }

  decrypt(ciphertext: Uint8Array | string) {
    return decrypt(
      this.receivingKey,
      this.receivingNonce,
      this.skippedIndexes,
      ciphertext
    )
  }
}

export function hello(): string {
  const safetyNumber = authenticate(
    Uint8Array.from([
      118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2,
      56, 252, 122, 177, 18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17,
      213, 153, 88, 124, 93, 136, 104, 111, 196, 208, 155, 156, 165, 31, 120,
      186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243, 24, 225, 91, 220,
      141, 150
    ]),
    Uint8Array.from([
      177, 67, 45, 125, 158, 190, 181, 222, 101, 149, 224, 200, 223, 235, 222,
      110, 67, 61, 200, 62, 29, 37, 150, 228, 137, 114, 143, 77, 115, 135, 143,
      103
    ])
  )
  return createFrom(safetyNumber).toString('base64url')
}
