import { createInitiator, createResponder, init } from '../src/autograph'

describe('Safety number', () => {
  const keyPairs = {
    alice: {
      publicKey: Uint8Array.from([
        91, 119, 85, 151, 32, 20, 121, 20, 19, 106, 90, 56, 141, 90, 16, 210,
        14, 244, 60, 251, 140, 48, 190, 65, 194, 35, 166, 246, 1, 209, 4, 33
      ]),
      privateKey: Uint8Array.from([
        43, 6, 246, 172, 137, 170, 33, 12, 118, 177, 111, 60, 19, 37, 65, 122,
        28, 34, 200, 251, 96, 35, 187, 52, 74, 224, 143, 39, 90, 51, 33, 140
      ])
    },
    bob: {
      publicKey: Uint8Array.from([
        232, 130, 200, 162, 218, 101, 75, 210, 196, 152, 235, 97, 118, 3, 241,
        131, 200, 140, 54, 155, 28, 46, 158, 76, 96, 4, 150, 61, 34, 13, 133,
        138
      ]),
      privateKey: Uint8Array.from([
        243, 11, 156, 139, 99, 129, 212, 8, 60, 53, 111, 123, 69, 158, 83, 255,
        187, 192, 29, 114, 69, 126, 243, 111, 122, 143, 170, 247, 140, 129, 60,
        0
      ])
    }
  }
  const safetyNumber = Uint8Array.from([
    52, 52, 57, 52, 50, 50, 53, 55, 54, 50, 48, 53, 51, 51, 49, 55, 56, 54, 48,
    50, 55, 53, 56, 48, 54, 52, 56, 52, 53, 49, 53, 55, 50, 49, 50, 54, 49, 50,
    50, 49, 57, 52, 53, 57, 52, 50, 55, 54, 49, 49, 54, 49, 57, 50, 52, 53, 52,
    57, 50, 54
  ])

  beforeAll(async () => {
    await init()
  })

  it('should allow Alice and Bob to calculate safety numbers', () => {
    const alice = createInitiator(keyPairs.alice)
    const bob = createResponder(keyPairs.bob)
    const a = alice.calculateSafetyNumber(keyPairs.bob.publicKey)
    const b = bob.calculateSafetyNumber(keyPairs.alice.publicKey)
    expect(a.safetyNumber).toEqual(safetyNumber)
    expect(b.safetyNumber).toEqual(safetyNumber)
  })
})
