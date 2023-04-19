import { Chunk } from 'stedy/bytes'

export type SafetyNumberFunction = (
  theirIdentityKey: BufferSource
) => Promise<Chunk>

export type CertifyFunction = (data?: BufferSource) => Promise<Chunk>

export type DecryptFunction = (message: BufferSource) => Promise<Chunk>

export type EncryptFunction = (message: BufferSource) => Promise<Chunk>

export type Certificate = { identityKey: BufferSource; signature: BufferSource }

export type VerifyFunction = (
  certificates: Certificate[] | Certificate,
  message?: BufferSource
) => Promise<boolean>

export type Session = {
  certify: CertifyFunction
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  verify: VerifyFunction
}

export type SessionFunction = (ciphertext: BufferSource) => Promise<Session>

export type Handshake = {
  handshake: Chunk
  establishSession: SessionFunction
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
  calculateSafetyNumber: SafetyNumberFunction
  ephemeralKey: Chunk
  performHandshake: HandshakeFunction
  identityKey: Chunk
}
