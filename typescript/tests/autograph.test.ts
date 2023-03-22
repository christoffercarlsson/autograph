import { importKey, verify as verifySignature } from 'stedy'
import { concat, createFrom } from 'stedy/bytes'
import {
  createAlice,
  createBob,
  createInitiator,
  generateKeyPair,
  generateResponder
} from '../src/autograph'
import { KeyPair, Party } from '../types'

const verifyOwnership = async (
  ownerIdentityKey: BufferSource,
  signerIdentityKey: BufferSource,
  signature: BufferSource,
  data?: BufferSource
) =>
  verifySignature(
    concat([data, ownerIdentityKey]),
    await importKey(signerIdentityKey, true, true),
    signature
  )

describe('The Autograph protocol', () => {
  const data = createFrom('Hello World')
  let aliceKeyPair: KeyPair
  let bobKeyPair: KeyPair
  let alice: Party
  let bob: Party
  beforeEach(async () => {
    aliceKeyPair = await generateKeyPair()
    bobKeyPair = await generateKeyPair()
    alice = await createAlice(aliceKeyPair)
    bob = await createBob(bobKeyPair)
  })

  it('should allow two parties to calculate safety numbers', async () => {
    const a = await alice.calculateSafetyNumber(bob.identityKey)
    const b = await bob.calculateSafetyNumber(alice.identityKey)
    expect(a.byteLength).toBe(60)
    expect(a).toEqual(b)
  })

  it('should allow Alice to send encrypted data to Bob', async () => {
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    const { encrypt } = await a.session(b.ciphertext)
    const { decrypt } = await b.session(a.ciphertext)
    const message = await encrypt(data)
    const result = await decrypt(message)
    expect(result).toEqual(data)
  })

  it('should allow Bob to send encrypted data to Alice', async () => {
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    const { decrypt } = await a.session(b.ciphertext)
    const { encrypt } = await b.session(a.ciphertext)
    const message = await encrypt(data)
    const result = await decrypt(message)
    expect(result).toEqual(data)
  })

  it("should allow Bob to certify Alice's ownership of her identity key and data", async () => {
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    const { encrypt } = await a.session(b.ciphertext)
    const { decrypt, certify } = await b.session(a.ciphertext)
    const message = await encrypt(data)
    const signature = await certify(await decrypt(message))
    expect(signature.byteLength).toBe(64)
    await expect(
      verifyOwnership(alice.identityKey, bob.identityKey, signature, data)
    ).resolves.toBe(true)
  })

  it("should allow Alice to certify Bob's ownership of his identity key and data", async () => {
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    const { decrypt, certify } = await a.session(b.ciphertext)
    const { encrypt } = await b.session(a.ciphertext)
    const message = await encrypt(data)
    const signature = await certify(await decrypt(message))
    expect(signature.byteLength).toBe(64)
    await expect(
      verifyOwnership(bob.identityKey, alice.identityKey, signature, data)
    ).resolves.toBe(true)
  })

  it("should allow Bob to certify Alice's ownership of her identity key", async () => {
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    const { certify } = await b.session(a.ciphertext)
    const signature = await certify()
    expect(signature.byteLength).toBe(64)
    await expect(
      verifyOwnership(alice.identityKey, bob.identityKey, signature)
    ).resolves.toBe(true)
  })

  it("should allow Alice to certify Bob's ownership of his identity key", async () => {
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    const { certify } = await a.session(b.ciphertext)
    const signature = await certify()
    expect(signature.byteLength).toBe(64)
    await expect(
      verifyOwnership(bob.identityKey, alice.identityKey, signature)
    ).resolves.toBe(true)
  })

  it("should allow Bob to verify Alice's ownership of her identity key and data based on Charlie's public key and signature", async () => {
    const charlie = await generateResponder()
    const c = await charlie.handshake(alice.identityKey, alice.ephemeralKey)
    let a = await alice.handshake(charlie.identityKey, charlie.ephemeralKey)
    let as = await a.session(c.ciphertext)
    const { decrypt, certify } = await c.session(a.ciphertext)
    let message = await as.encrypt(data)
    const signature = await certify(await decrypt(message))
    alice = await createAlice(aliceKeyPair)
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    as = await a.session(b.ciphertext)
    const { verify } = await b.session(a.ciphertext)
    message = await as.encrypt(data)
    const verified = await verify(
      [{ identityKey: charlie.identityKey, signature }],
      message
    )
    expect(verified).toBe(true)
  })

  it("should allow Alice to verify Bob's ownership of her identity key and data based on Charlie's public key and signature", async () => {
    bob = await createInitiator(bobKeyPair)
    const charlie = await generateResponder()
    const c = await charlie.handshake(bob.identityKey, bob.ephemeralKey)
    let b = await bob.handshake(charlie.identityKey, charlie.ephemeralKey)
    let bs = await b.session(c.ciphertext)
    const { decrypt, certify } = await c.session(b.ciphertext)
    let message = await bs.encrypt(data)
    const signature = await certify(await decrypt(message))
    bob = await createBob(bobKeyPair)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    bs = await b.session(a.ciphertext)
    const { verify } = await a.session(b.ciphertext)
    message = await bs.encrypt(data)
    const verified = await verify(
      [{ identityKey: charlie.identityKey, signature }],
      message
    )
    expect(verified).toBe(true)
  })

  it("should allow Bob to verify Alice's ownership of her identity key based on Charlie's public key and signature", async () => {
    const charlie = await generateResponder()
    const c = await charlie.handshake(alice.identityKey, alice.ephemeralKey)
    let a = await alice.handshake(charlie.identityKey, charlie.ephemeralKey)
    const { certify } = await c.session(a.ciphertext)
    const signature = await certify()
    alice = await createAlice(aliceKeyPair)
    const b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    const { verify } = await b.session(a.ciphertext)
    const verified = await verify([
      { identityKey: charlie.identityKey, signature }
    ])
    expect(verified).toBe(true)
  })

  it("should allow Alice to verify Bob's ownership of his identity key based on Charlie's public key and signature", async () => {
    bob = await createInitiator(bobKeyPair)
    const charlie = await generateResponder()
    const c = await charlie.handshake(bob.identityKey, bob.ephemeralKey)
    let b = await bob.handshake(charlie.identityKey, charlie.ephemeralKey)
    const { certify } = await c.session(b.ciphertext)
    const signature = await certify()
    bob = await createBob(bobKeyPair)
    const a = await alice.handshake(bob.identityKey, bob.ephemeralKey)
    b = await bob.handshake(alice.identityKey, alice.ephemeralKey)
    const { verify } = await a.session(b.ciphertext)
    const verified = await verify([
      { identityKey: charlie.identityKey, signature }
    ])
    expect(verified).toBe(true)
  })
})
