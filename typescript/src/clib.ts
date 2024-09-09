import wasmReady from '../wasm/autograph.js'

type EmscriptenModule = {
  _calloc: (size: number, elementSize: number) => number
  _free: (ptr: number) => void
  ccall: (
    name: string,
    returnType: string,
    types: string[],
    values: (number | boolean)[]
  ) => number | boolean
  getRandomValue: () => number
  HEAPU8: Uint8Array
}

type EmscriptenValue = number | boolean | Uint8Array | Uint32Array

type EmscriptenAddressPool = Map<number, Uint8Array | Uint32Array>

let Module: EmscriptenModule = null

const allocate = (
  addresses: EmscriptenAddressPool,
  args: EmscriptenValue[]
) => {
  const types: string[] = []
  const values = args.map((value) => {
    if (ArrayBuffer.isView(value)) {
      types.push('number')
      const address = Module._calloc(value.length, value.BYTES_PER_ELEMENT)
      addresses.set(address, value)
      Module.HEAPU8.set(
        new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
        address
      )
      return address
    }
    types.push(typeof value)
    return value
  })
  return { types, values }
}

const deallocate = (addresses: EmscriptenAddressPool) => {
  addresses.forEach((value, address) => {
    if (value instanceof Uint32Array) {
      value.set(new Uint32Array(Module.HEAPU8.buffer, address, value.length))
    } else {
      value.set(new Uint8Array(Module.HEAPU8.buffer, address, value.length))
    }
    Module._free(address)
  })
}

const call = (
  name: string,
  returnType: string | null,
  ...args: EmscriptenValue[]
) => {
  const addresses: EmscriptenAddressPool = new Map()
  const { types, values } = allocate(addresses, args)
  const result = Module.ccall(name, returnType, types, values)
  deallocate(addresses)
  return result
}

const autograph_ready = () => call('autograph_ready', 'boolean') as boolean

export const ready = async () => {
  if (!Module) {
    Module = (await wasmReady()) as EmscriptenModule
    try {
      const getRandomValue = () => {
        const view = new Uint32Array(1)
        globalThis.crypto.getRandomValues(view)
        return view[0] >>> 0
      }
      getRandomValue()
      Module.getRandomValue = getRandomValue
    } catch {
      throw new Error('No secure random number generator found')
    }
    if (!autograph_ready()) {
      throw new Error('Initialization failed')
    }
  }
}

export const autograph_identity_key_pair = (key_pair: Uint8Array) =>
  call('autograph_identity_key_pair', 'boolean', key_pair) as boolean

export const autograph_session_key_pair = (key_pair: Uint8Array) =>
  call('autograph_session_key_pair', 'boolean', key_pair) as boolean

export const autograph_get_identity_public_key = (
  public_key: Uint8Array,
  key_pair: Uint8Array
) => call('autograph_get_identity_public_key', null, public_key, key_pair)

export const autograph_get_session_public_key = (
  public_key: Uint8Array,
  key_pair: Uint8Array
) => call('autograph_get_session_public_key', null, public_key, key_pair)

export const autograph_authenticate = (
  safety_number: Uint8Array,
  our_identity_key_pair: Uint8Array,
  our_id: Uint8Array,
  our_id_size: number,
  their_identity_key: Uint8Array,
  their_id: Uint8Array,
  their_id_size: number
) =>
  call(
    'autograph_authenticate',
    'boolean',
    safety_number,
    our_identity_key_pair,
    our_id,
    our_id_size,
    their_identity_key,
    their_id,
    their_id_size
  ) as boolean

export const autograph_certify = (
  signature: Uint8Array,
  our_identity_key_pair: Uint8Array,
  their_identity_key: Uint8Array,
  data: Uint8Array,
  data_size: number
) =>
  call(
    'autograph_certify',
    'boolean',
    signature,
    our_identity_key_pair,
    their_identity_key,
    data,
    data_size
  ) as boolean

export const autograph_verify = (
  owner_identity_key: Uint8Array,
  certifier_identity_key: Uint8Array,
  signature: Uint8Array,
  data: Uint8Array,
  data_size: number
) =>
  call(
    'autograph_verify',
    'boolean',
    owner_identity_key,
    certifier_identity_key,
    signature,
    data,
    data_size
  ) as boolean

export const autograph_key_exchange = (
  transcript: Uint8Array,
  our_signature: Uint8Array,
  sending_key: Uint8Array,
  receiving_key: Uint8Array,
  is_initiator: boolean,
  our_identity_key_pair: Uint8Array,
  our_session_key_pair: Uint8Array,
  their_identity_key: Uint8Array,
  their_session_key: Uint8Array
) =>
  call(
    'autograph_key_exchange',
    'boolean',
    transcript,
    our_signature,
    sending_key,
    receiving_key,
    is_initiator,
    our_identity_key_pair,
    our_session_key_pair,
    their_identity_key,
    their_session_key
  ) as boolean

export const autograph_verify_key_exchange = (
  transcript: Uint8Array,
  our_identity_key_pair: Uint8Array,
  their_identity_key: Uint8Array,
  their_signature: Uint8Array
) =>
  call(
    'autograph_verify_key_exchange',
    'boolean',
    transcript,
    our_identity_key_pair,
    their_identity_key,
    their_signature
  ) as boolean

export const autograph_generate_secret_key = (key: Uint8Array) =>
  call('autograph_generate_secret_key', 'boolean', key) as boolean

export const autograph_encrypt = (
  index: Uint32Array,
  ciphertext: Uint8Array,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  plaintext_size: number
) =>
  call(
    'autograph_encrypt',
    'boolean',
    index,
    ciphertext,
    key,
    nonce,
    plaintext,
    plaintext_size
  ) as boolean

export const autograph_decrypt = (
  index: Uint32Array,
  plaintext: Uint8Array,
  plaintext_size: Uint32Array,
  key: Uint8Array,
  nonce: Uint8Array,
  skipped_indexes: Uint8Array,
  skipped_indexes_size: number,
  ciphertext: Uint8Array,
  ciphertext_size: number
) =>
  call(
    'autograph_decrypt',
    'boolean',
    index,
    plaintext,
    plaintext_size,
    key,
    nonce,
    skipped_indexes,
    skipped_indexes_size,
    ciphertext,
    ciphertext_size
  ) as boolean

export const autograph_skipped_indexes_size = (count: number) =>
  call('autograph_skipped_indexes_size', 'number', count) as number

export const autograph_identity_key_pair_size = () =>
  call('autograph_identity_key_pair_size', 'number') as number

export const autograph_session_key_pair_size = () =>
  call('autograph_session_key_pair_size', 'number') as number

export const autograph_identity_public_key_size = () =>
  call('autograph_identity_public_key_size', 'number') as number

export const autograph_session_public_key_size = () =>
  call('autograph_session_public_key_size', 'number') as number

export const autograph_nonce_size = () =>
  call('autograph_nonce_size', 'number') as number

export const autograph_safety_number_size = () =>
  call('autograph_safety_number_size', 'number') as number

export const autograph_secret_key_size = () =>
  call('autograph_secret_key_size', 'number') as number

export const autograph_signature_size = () =>
  call('autograph_signature_size', 'number') as number

export const autograph_transcript_size = () =>
  call('autograph_transcript_size', 'number') as number

export const autograph_ciphertext_size = (plaintext_size: number) =>
  call('autograph_ciphertext_size', 'number', plaintext_size) as number

export const autograph_plaintext_size = (ciphertext_size: number) =>
  call('autograph_plaintext_size', 'number', ciphertext_size) as number

export const autograph_use_key_pairs = (
  identity_key_pair: Uint8Array,
  session_key_pair: Uint8Array,
  our_identity_key_pair: Uint8Array,
  our_session_key_pair: Uint8Array
) =>
  call(
    'autograph_use_key_pairs',
    null,
    identity_key_pair,
    session_key_pair,
    our_identity_key_pair,
    our_session_key_pair
  )

export const autograph_use_public_keys = (
  identity_key: Uint8Array,
  session_key: Uint8Array,
  their_identity_key: Uint8Array,
  their_session_key: Uint8Array
) =>
  call(
    'autograph_use_public_keys',
    null,
    identity_key,
    session_key,
    their_identity_key,
    their_session_key
  )
