export type SignResult = Uint8Array | Promise<Uint8Array>

export type SignDataFunction = (data: Uint8Array) => SignResult

export type SignIdentityFunction = () => SignResult

export type DecryptFunction = (message: Uint8Array) => [bigint, Uint8Array]

export type EncryptFunction = (data: Uint8Array) => [bigint, Uint8Array]

export type VerifyDataFunction = (
  certificates: Uint8Array,
  data: Uint8Array
) => boolean

export type VerifyIdentityFunction = (certificates: Uint8Array) => boolean

export type Channel = {
  decrypt: DecryptFunction
  encrypt: EncryptFunction
  signData: SignDataFunction
  signIdentity: SignIdentityFunction
  verifyData: VerifyDataFunction
  verifyIdentity: VerifyIdentityFunction
}

export type KeyExchangeVerificationFunction = (
  theirHandshake: Uint8Array
) => Channel

export type KeyPair = {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export type SignFunction = (subject: Uint8Array) => SignResult

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
