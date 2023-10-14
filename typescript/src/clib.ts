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
      const address = Module._calloc(value.byteLength, 1)
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

const call = (name: string, returnType: string, ...args: EmscriptenValue[]) => {
  const addresses: EmscriptenAddressPool = new Map()
  const { types, values } = allocate(addresses, args)
  const result = Module.ccall(name, returnType, types, values)
  deallocate(addresses)
  return result
}

export const autograph_ciphertext_size = (plaintext_size: number) =>
  call('autograph_ciphertext_size', 'number', plaintext_size) as number

export const autograph_decrypt = (
  plaintext: Uint8Array,
  plaintext_size: Uint8Array,
  message_index: Uint8Array,
  decrypt_index: Uint8Array,
  skipped_keys: Uint8Array,
  key: Uint8Array,
  message: Uint8Array,
  message_size: number
) =>
  call(
    'autograph_decrypt',
    'number',
    plaintext,
    plaintext_size,
    message_index,
    decrypt_index,
    skipped_keys,
    key,
    message,
    message_size
  ) === 0

export const autograph_encrypt = (
  message: Uint8Array,
  message_index: Uint8Array,
  key: Uint8Array,
  plaintext: Uint8Array,
  plaintext_size: number
) =>
  call(
    'autograph_encrypt',
    'number',
    message,
    message_index,
    key,
    plaintext,
    plaintext_size
  ) === 0

export const autograph_init = async () => {
  if (!Module) {
    Module = (await wasmModule()) as EmscriptenModule
  }
  return call('autograph_init', 'number') === 0
}

export const autograph_key_exchange = (
  transcript: Uint8Array,
  handshake: Uint8Array,
  our_secret_key: Uint8Array,
  their_secret_key: Uint8Array,
  is_initiator: number,
  our_private_identity_key: Uint8Array,
  our_public_identity_key: Uint8Array,
  our_private_ephemeral_key: Uint8Array,
  our_public_ephemeral_key: Uint8Array,
  their_public_identity_key: Uint8Array,
  their_public_ephemeral_key: Uint8Array
) =>
  call(
    'autograph_key_exchange',
    'number',
    transcript,
    handshake,
    our_secret_key,
    their_secret_key,
    is_initiator,
    our_private_identity_key,
    our_public_identity_key,
    our_private_ephemeral_key,
    our_public_ephemeral_key,
    their_public_identity_key,
    their_public_ephemeral_key
  ) === 0

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
    'number',
    handshake,
    our_secret_key,
    their_secret_key,
    is_initiator,
    our_signature,
    our_private_ephemeral_key,
    their_public_ephemeral_key
  ) === 0

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
    'number',
    transcript,
    is_initiator,
    our_identity_key,
    our_ephemeral_key,
    their_identity_key,
    their_ephemeral_key
  ) === 0

export const autograph_key_exchange_verify = (
  transcript: Uint8Array,
  their_identity_key: Uint8Array,
  their_secret_key: Uint8Array,
  ciphertext: Uint8Array
) =>
  call(
    'autograph_key_exchange_verify',
    'number',
    transcript,
    their_identity_key,
    their_secret_key,
    ciphertext
  ) === 0

export const autograph_key_pair_ephemeral = (
  private_key: Uint8Array,
  public_key: Uint8Array
) =>
  call('autograph_key_pair_ephemeral', 'number', private_key, public_key) === 0

export const autograph_key_pair_identity = (
  private_key: Uint8Array,
  public_key: Uint8Array
) =>
  call('autograph_key_pair_identity', 'number', private_key, public_key) === 0

export const autograph_plaintext_size = (ciphertext_size: number) =>
  call('autograph_plaintext_size', 'number', ciphertext_size) as number

export const autograph_read_uint32 = (bytes: Uint8Array) =>
  call('autograph_read_uint32', 'number', bytes) as number

export const autograph_read_uint64 = (bytes: Uint8Array) =>
  call('autograph_read_uint64', 'bigint', bytes) as bigint

export const autograph_safety_number = (
  safety_number: Uint8Array,
  our_identity_key: Uint8Array,
  their_identity_key: Uint8Array
) =>
  call(
    'autograph_safety_number',
    'number',
    safety_number,
    our_identity_key,
    their_identity_key
  ) === 0

export const autograph_sign_data = (
  signature: Uint8Array,
  our_private_key: Uint8Array,
  their_public_key: Uint8Array,
  data: Uint8Array,
  data_size: number
) =>
  call(
    'autograph_sign_data',
    'number',
    signature,
    our_private_key,
    their_public_key,
    data,
    data_size
  ) === 0

export const autograph_sign_identity = (
  signature: Uint8Array,
  our_private_key: Uint8Array,
  their_public_key: Uint8Array
) =>
  call(
    'autograph_sign_identity',
    'number',
    signature,
    our_private_key,
    their_public_key
  ) === 0

export const autograph_sign_subject = (
  signature: Uint8Array,
  private_key: Uint8Array,
  subject: Uint8Array,
  subject_size: number
) =>
  call(
    'autograph_sign_subject',
    'number',
    signature,
    private_key,
    subject,
    subject_size
  ) === 0

export const autograph_subject = (
  subject: Uint8Array,
  their_public_key: Uint8Array,
  data: Uint8Array,
  data_size: number
) =>
  call(
    'autograph_subject',
    'number',
    subject,
    their_public_key,
    data,
    data_size
  ) === 0

export const autograph_verify_data = (
  their_public_key: Uint8Array,
  certificates: Uint8Array,
  certificate_count: number,
  data: Uint8Array,
  data_size: number
) =>
  call(
    'autograph_verify_data',
    'number',
    their_public_key,
    certificates,
    certificate_count,
    data,
    data_size
  ) === 0

export const autograph_verify_identity = (
  their_public_key: Uint8Array,
  certificates: Uint8Array,
  certificate_count: number
) =>
  call(
    'autograph_verify_identity',
    'number',
    their_public_key,
    certificates,
    certificate_count
  ) === 0
