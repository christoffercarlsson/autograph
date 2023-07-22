export type SafetyNumberResult = {
  success: boolean
  safetyNumber: BufferSource
}

export type SafetyNumberFunction = (
  theirIdentityKey: BufferSource
) => Promise<SafetyNumberResult>

export type CertificationResult = {
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

export type CertifyFunction = (
  data?: BufferSource
) => Promise<CertificationResult>

export type DecryptFunction = (
  message: BufferSource
) => Promise<DecryptionResult>

export type EncryptFunction = (data: BufferSource) => Promise<EncryptionResult>

export type VerifyFunction = (
  certificates: BufferSource,
  data?: BufferSource
) => Promise<boolean>

export type Session = {
  certify: CertifyFunction
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  verify: VerifyFunction
}

export type SessionResult = {
  success: boolean
  session: Session
}

export type SessionFunction = (message: BufferSource) => Promise<SessionResult>

export type Handshake = {
  message: BufferSource
  establishSession: SessionFunction
}

export type HandshakeResult = {
  success: boolean
  handshake: Handshake
}

export type HandshakeFunction = (
  theirIdentityKey: BufferSource,
  theirEphemeralKey: BufferSource
) => Promise<HandshakeResult>

export type KeyPair = {
  publicKey: BufferSource
  privateKey: BufferSource
}

export type KeyPairResult = {
  success: boolean
  keyPair: KeyPair
}

export type Party = {
  calculateSafetyNumber: SafetyNumberFunction
  performHandshake: HandshakeFunction
}
