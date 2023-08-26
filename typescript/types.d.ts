export type SafetyNumberResult = {
  success: boolean
  safetyNumber: BufferSource
}

export type SafetyNumberFunction = (
  theirIdentityKey: BufferSource
) => Promise<SafetyNumberResult>

export type SignResult = {
  success: boolean
  signature: BufferSource
}

export type DecryptionResult = {
  success: boolean
  data: BufferSource
}

export type EncryptionResult = {
  success: boolean
  message: BufferSource
}

export type SignDataFunction = (data: BufferSource) => Promise<SignResult>

export type SignIdentityFunction = () => Promise<SignResult>

export type DecryptFunction = (
  message: BufferSource
) => Promise<DecryptionResult>

export type EncryptFunction = (data: BufferSource) => Promise<EncryptionResult>

export type VerifyDataFunction = (
  certificates: BufferSource,
  data: BufferSource
) => Promise<boolean>

export type VerifyIdentityFunction = (
  certificates: BufferSource
) => Promise<boolean>

export type Session = {
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  signData: SignDataFunction
  signIdentity: SignIdentityFunction
  verifyData: VerifyDataFunction
  verifyIdentity: VerifyIdentityFunction
}

export type KeyExchangeVerificationResult = {
  success: boolean
  session: Session
}

export type KeyExchangeVerificationFunction = (
  handshake: BufferSource
) => Promise<KeyExchangeVerificationResult>

export type KeyPair = {
  publicKey: BufferSource
  privateKey: BufferSource
}

export type KeyPairResult = {
  success: boolean
  keyPair: KeyPair
}

export type KeyExchange = {
  handshake: BufferSource
  verify: KeyExchangeVerificationFunction
}

export type KeyExchangeResult = {
  success: boolean
  keyExchange: KeyExchange
}

export type KeyExchangeFunction = (
  ourEphemeralKeyPair: KeyPair,
  theirIdentityKey: BufferSource,
  theirEphemeralKey: BufferSource
) => Promise<KeyExchangeResult>

export type Party = {
  calculateSafetyNumber: SafetyNumberFunction
  performKeyExchange: KeyExchangeFunction
}

export type SignFunction = (
  subject: BufferSource
) => Promise<SignResult> | SignResult
