export type SafetyNumberResult = {
  success: boolean
  safetyNumber: Uint8Array
}

export type SafetyNumberFunction = (
  theirIdentityKey: Uint8Array
) => SafetyNumberResult

export type SignResult = {
  success: boolean
  signature: Uint8Array
}

export type DecryptionResult = {
  success: boolean
  index: bigint
  data: Uint8Array
}

export type EncryptionResult = {
  success: boolean
  index: bigint
  message: Uint8Array
}

export type SignDataFunction = (
  data: Uint8Array
) => SignResult | Promise<SignResult>

export type SignIdentityFunction = () => SignResult | Promise<SignResult>

export type DecryptFunction = (message: Uint8Array) => DecryptionResult

export type EncryptFunction = (data: Uint8Array) => EncryptionResult

export type VerifyDataFunction = (
  certificates: Uint8Array,
  data: Uint8Array
) => boolean

export type VerifyIdentityFunction = (certificates: Uint8Array) => boolean

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
  handshake: Uint8Array
) => KeyExchangeVerificationResult

export type KeyPair = {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export type KeyPairResult = {
  success: boolean
  keyPair: KeyPair
}

export type KeyExchange = {
  handshake: Uint8Array
  verify: KeyExchangeVerificationFunction
}

export type KeyExchangeResult = {
  success: boolean
  keyExchange: KeyExchange
}

export type KeyExchangeFunction = (
  ourEphemeralKeyPair: KeyPair,
  theirIdentityKey: Uint8Array,
  theirEphemeralKey: Uint8Array
) => Promise<KeyExchangeResult>

export type Party = {
  calculateSafetyNumber: SafetyNumberFunction
  performKeyExchange: KeyExchangeFunction
}

export type SignFunction = (
  subject: Uint8Array
) => Promise<SignResult> | SignResult

export type EmscriptenModule = {
  _calloc: (size: number, elementSize: number) => number
  _free: (ptr: number) => void
  ccall: (
    name: string,
    returnType: string,
    types: string[],
    values: (number | bigint)[]
  ) => number | bigint
  HEAPU8: Uint8Array
}

export type EmscriptenValue = number | bigint | Uint8Array

export type EmscriptenAddressPool = Map<number, Uint8Array>
