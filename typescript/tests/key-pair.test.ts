import {
  generateEphemeralKeyPair,
  generateIdentityKeyPair,
  init
} from '../src/autograph'

describe('Key pair', () => {
  const emptyKey = new Uint8Array(32)

  beforeAll(async () => {
    await init()
  })

  it('should generate ephemeral key pairs', async () => {
    const { success, keyPair } = await generateEphemeralKeyPair()
    expect(success).toBe(true)
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.privateKey.byteLength).toBe(32)
    expect(keyPair.publicKey.byteLength).toBe(32)
    expect(keyPair.privateKey).not.toEqual(emptyKey)
    expect(keyPair.publicKey).not.toEqual(emptyKey)
  })

  it('should generate identity key pairs', async () => {
    const { success, keyPair } = await generateIdentityKeyPair()
    expect(success).toBe(true)
    expect(keyPair.privateKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.publicKey).toBeInstanceOf(Uint8Array)
    expect(keyPair.privateKey.byteLength).toBe(32)
    expect(keyPair.publicKey.byteLength).toBe(32)
    expect(keyPair.privateKey).not.toEqual(emptyKey)
    expect(keyPair.publicKey).not.toEqual(emptyKey)
  })
})
