import * as Autograph from 'autograph-protocol'

const authenticate = (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array
): [boolean, Uint8Array] => {
  try {
    const safetyNumber = Autograph.authenticate(
      ourIdentityKeyPair,
      theirIdentityKey
    )
    return [true, safetyNumber]
  } catch {
    return [false, new Uint8Array(64)]
  }
}

const certify = (
  ourIdentityKeyPair: Uint8Array,
  theirIdentityKey: Uint8Array,
  data?: Uint8Array
): [boolean, Uint8Array] => {
  try {
    const signature = Autograph.certify(
      ourIdentityKeyPair,
      theirIdentityKey,
      data
    )
    return [true, signature]
  } catch {
    return [false, new Uint8Array(64)]
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

const ready = async (): Promise<boolean> => {
  try {
    await Autograph.ready()
    return true
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
): [boolean, Uint8Array, Uint8Array, Uint8Array, Uint8Array] => {
  try {
    const [transcript, ourSignature, sendingKey, receivingKey] =
      Autograph.keyExchange(
        isInitiator,
        ourIdentityKeyPair,
        ourSessionKeyPair,
        theirIdentityKey,
        theirSessionKey
      )
    return [true, transcript, ourSignature, sendingKey, receivingKey]
  } catch {
    return [
      false,
      new Uint8Array(64),
      new Uint8Array(64),
      new Uint8Array(32),
      new Uint8Array(32)
    ]
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

const generateIdentityKeyPair = (): [boolean, Uint8Array] => {
  try {
    const keyPair = Autograph.generateIdentityKeyPair()
    return [true, keyPair]
  } catch {
    return [false, new Uint8Array(64)]
  }
}

const generateSessionKeyPair = (): [boolean, Uint8Array] => {
  try {
    const keyPair = Autograph.generateSessionKeyPair()
    return [true, keyPair]
  } catch {
    return [false, new Uint8Array(64)]
  }
}

const getIdentityPublicKey = (keyPair: Uint8Array): Uint8Array => {
  try {
    const publicKey = Autograph.getIdentityPublicKey(keyPair)
    return publicKey
  } catch {
    return new Uint8Array(32)
  }
}

const getSessionPublicKey = (keyPair: Uint8Array): Uint8Array => {
  try {
    const publicKey = Autograph.getSessionPublicKey(keyPair)
    return publicKey
  } catch {
    return new Uint8Array(32)
  }
}

const getPublicKeys = (
  identityKeyPair: Uint8Array,
  sessionKeyPair: Uint8Array
): [Uint8Array, Uint8Array] => {
  try {
    const [identityKey, sessionKey] = Autograph.getPublicKeys(
      identityKeyPair,
      sessionKeyPair
    )
    return [identityKey, sessionKey]
  } catch {
    return [new Uint8Array(32), new Uint8Array(32)]
  }
}

const createNonce = (): Uint8Array => {
  try {
    const nonce = Autograph.createNonce()
    return nonce
  } catch {
    return new Uint8Array(12)
  }
}

const generateSecretKey = (): [boolean, Uint8Array] => {
  try {
    const key = Autograph.generateSecretKey()
    return [true, key]
  } catch {
    return [false, new Uint8Array(32)]
  }
}

const encrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array
): [boolean, number, Uint8Array] => {
  try {
    const [index, ciphertext] = Autograph.encrypt(key, nonce, plaintext)
    return [true, index, ciphertext]
  } catch {
    return [false, 0, new Uint8Array(plaintext.length + 16)]
  }
}

const decrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  skippedIndexes: Uint8Array,
  ciphertext: Uint8Array
): [boolean, number, Uint8Array] => {
  try {
    const [index, plaintext] = Autograph.decrypt(
      key,
      nonce,
      new Uint32Array(skippedIndexes.buffer),
      ciphertext
    )
    return [true, index, plaintext]
  } catch {
    return [false, 0, new Uint8Array(ciphertext.length - 16)]
  }
}

export default {
  authenticate,
  certify,
  verify,
  ready,
  keyExchange,
  verifyKeyExchange,
  generateIdentityKeyPair,
  generateSessionKeyPair,
  getIdentityPublicKey,
  getSessionPublicKey,
  getPublicKeys,
  createNonce,
  generateSecretKey,
  encrypt,
  decrypt
}
