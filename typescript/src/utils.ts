export const bytesToIndex = (bytes: Uint8Array) =>
  new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0)

export const createHandshakeBytes = () => new Uint8Array(80)

export const createMessageBytes = (size: number) => new Uint8Array(size + 16)

export const createPlaintextBytes = (size: number) => new Uint8Array(size - 16)

export const createPrivateKeyBytes = () => new Uint8Array(32)

export const createPublicKeyBytes = () => new Uint8Array(32)

export const createSafetyNumberBytes = () => new Uint8Array(60)

export const createSecretKeyBytes = () => new Uint8Array(32)

export const createSignatureBytes = () => new Uint8Array(64)

export const createSubjectBytes = (size: number) => new Uint8Array(size + 32)

export const createTranscriptBytes = () => new Uint8Array(128)
