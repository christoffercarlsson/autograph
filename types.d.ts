export type KeyPair = {
  publicKey: Uint8Array
  privateKey: Uint8Array
}

export type SignFunction = (
  subject: Uint8Array
) => Uint8Array | Promise<Uint8Array>

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
