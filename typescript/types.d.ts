import { Chunk } from 'stedy/bytes'

export type CalculateSafetyNumberFunction = (
  theirIdentityKey: BufferSource
) => Promise<Chunk>

export type CertifyFunction = (data?: BufferSource) => Promise<Chunk>

export type DecryptFunction = (message: BufferSource) => Promise<Chunk>

export type EncryptFunction = (message: BufferSource) => Promise<Chunk>

export type Certificate = { identityKey: BufferSource; signature: BufferSource }

export type VerifyFunction = (
  certificates: Certificate[],
  message?: BufferSource
) => Promise<boolean>

export type Session = {
  certify: CertifyFunction
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  verify: VerifyFunction
}

export type SessionFunction = (ciphertext: BufferSource) => Promise<Session>

export type SecretKeys = {
  ourSecretKey: Chunk
  theirSecretKey: Chunk
}

export type Handshake = {
  ciphertext: Chunk
  session: SessionFunction
}

export type HandshakeFunction = (
  theirIdentityKey: BufferSource,
  theirEphemeralKey: BufferSource
) => Promise<Handshake>

export type KeyPair = {
  publicKey: BufferSource
  privateKey: BufferSource
}

export type Party = {
  calculateSafetyNumber: CalculateSafetyNumberFunction
  ephemeralKey: Chunk
  handshake: HandshakeFunction
  identityKey: Chunk
}
