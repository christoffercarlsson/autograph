import { Chunk as Bytes } from 'stedy/bytes'

export type SafetyNumberFunction = (
  theirIdentityKey: BufferSource
) => Promise<Bytes>

export type CertifyFunction = (data?: BufferSource) => Promise<Bytes>

export type DecryptFunction = (message: BufferSource) => Promise<Bytes>

export type EncryptFunction = (message: BufferSource) => Promise<Bytes>

export type VerifyFunction = (
  certificates: BufferSource,
  message?: BufferSource
) => Promise<boolean>

export type Session = {
  certify: CertifyFunction
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  verify: VerifyFunction
}

export type SessionFunction = (message: BufferSource) => Promise<Session>

export type Handshake = {
  message: Bytes
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
  performHandshake: HandshakeFunction
}
