import wasmModule from '../wasm/autograph.js'
import {
  EmscriptenAddressPool,
  EmscriptenValue,
  EmscriptenModule
} from '../types'

let Module: EmscriptenModule = null

const allocate = (
  addresses: EmscriptenAddressPool,
  args: EmscriptenValue[]
) => {
  const types: string[] = []
  const values = args.map((value) => {
    if (value instanceof Uint8Array) {
      types.push('number')
      const address = Module._malloc(value.byteLength)
      addresses.set(address, value)
      Module.HEAPU8.set(value, address)
      return address
    }
    types.push(typeof value)
    return value
  })
  return { types, values }
}

const deallocate = (addresses: EmscriptenAddressPool) => {
  addresses.forEach((value, address) => {
    value.set(Module.HEAPU8.subarray(address, address + value.byteLength))
    Module._free(address)
  })
}

const call = async (name: string, ...args: EmscriptenValue[]) => {
  if (!Module) {
    Module = (await wasmModule()) as EmscriptenModule
  }
  const addresses: EmscriptenAddressPool = new Map()
  const { types, values } = allocate(addresses, args)
  const result = Module.ccall(name, 'number', types, values)
  deallocate(addresses)
  return result === 0
}

export const autograph_decrypt = (
  plaintext: Uint8Array,
  key: Uint8Array,
  message: Uint8Array,
  message_size: bigint
) => call('autograph_decrypt', plaintext, key, message, message_size)

export const autograph_encrypt = (
  message: Uint8Array,
  key: Uint8Array,
  index: bigint,
  plaintext: Uint8Array,
  plaintext_size: bigint
) => call('autograph_encrypt', message, key, index, plaintext, plaintext_size)

export const autograph_init = async () => call('autograph_init')

export const autograph_key_exchange = (
  transcript: Uint8Array,
  handshake: Uint8Array,
  our_secret_key: Uint8Array,
  their_secret_key: Uint8Array,
  is_initiator: number,
  our_private_identity_key: Uint8Array,
  our_private_ephemeral_key: Uint8Array,
  our_public_ephemeral_key: Uint8Array,
  their_public_identity_key: Uint8Array,
  their_public_ephemeral_key: Uint8Array
) =>
  call(
    'autograph_key_exchange',
    transcript,
    handshake,
    our_secret_key,
    their_secret_key,
    is_initiator,
    our_private_identity_key,
    our_private_ephemeral_key,
    our_public_ephemeral_key,
    their_public_identity_key,
    their_public_ephemeral_key
  )

export const autograph_key_exchange_signature = (
  handshake: Uint8Array,
  our_secret_key: Uint8Array,
  their_secret_key: Uint8Array,
  is_initiator: number,
  our_signature: Uint8Array,
  our_private_ephemeral_key: Uint8Array,
  their_public_ephemeral_key: Uint8Array
) =>
  call(
    'autograph_key_exchange_signature',
    handshake,
    our_secret_key,
    their_secret_key,
    is_initiator,
    our_signature,
    our_private_ephemeral_key,
    their_public_ephemeral_key
  )

export const autograph_key_exchange_transcript = (
  transcript: Uint8Array,
  is_initiator: number,
  our_identity_key: Uint8Array,
  our_ephemeral_key: Uint8Array,
  their_identity_key: Uint8Array,
  their_ephemeral_key: Uint8Array
) =>
  call(
    'autograph_key_exchange_transcript',
    transcript,
    is_initiator,
    our_identity_key,
    our_ephemeral_key,
    their_identity_key,
    their_ephemeral_key
  )

export const autograph_key_exchange_verify = (
  transcript: Uint8Array,
  their_identity_key: Uint8Array,
  their_secret_key: Uint8Array,
  ciphertext: Uint8Array
) =>
  call(
    'autograph_key_exchange_verify',
    transcript,
    their_identity_key,
    their_secret_key,
    ciphertext
  )

export const autograph_key_pair_ephemeral = (
  private_key: Uint8Array,
  public_key: Uint8Array
) => call('autograph_key_pair_ephemeral', private_key, public_key)

export const autograph_key_pair_identity = (
  private_key: Uint8Array,
  public_key: Uint8Array
) => call('autograph_key_pair_identity', private_key, public_key)

export const autograph_safety_number = (
  safety_number: Uint8Array,
  our_identity_key: Uint8Array,
  their_identity_key: Uint8Array
) =>
  call(
    'autograph_safety_number',
    safety_number,
    our_identity_key,
    their_identity_key
  )

export const autograph_sign_data = (
  signature: Uint8Array,
  our_private_key: Uint8Array,
  their_public_key: Uint8Array,
  data: Uint8Array,
  data_size: bigint
) =>
  call(
    'autograph_sign_data',
    signature,
    our_private_key,
    their_public_key,
    data,
    data_size
  )

export const autograph_sign_identity = (
  signature: Uint8Array,
  our_private_key: Uint8Array,
  their_public_key: Uint8Array
) =>
  call('autograph_sign_identity', signature, our_private_key, their_public_key)

export const autograph_sign_subject = (
  signature: Uint8Array,
  private_key: Uint8Array,
  subject: Uint8Array,
  subject_size: bigint
) =>
  call('autograph_sign_subject', signature, private_key, subject, subject_size)

export const autograph_subject = (
  subject: Uint8Array,
  their_public_key: Uint8Array,
  data: Uint8Array,
  data_size: bigint
) => call('autograph_subject', subject, their_public_key, data, data_size)

export const autograph_verify_data = (
  their_public_key: Uint8Array,
  certificates: Uint8Array,
  certificate_count: bigint,
  data: Uint8Array,
  data_size: bigint
) =>
  call(
    'autograph_verify_data',
    their_public_key,
    certificates,
    certificate_count,
    data,
    data_size
  )

export const autograph_verify_identity = (
  their_public_key: Uint8Array,
  certificates: Uint8Array,
  certificate_count: bigint
) =>
  call(
    'autograph_verify_identity',
    their_public_key,
    certificates,
    certificate_count
  )
