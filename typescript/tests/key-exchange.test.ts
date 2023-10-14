import {
  createInitiator,
  createResponder,
  createSign,
  init
} from '../src/autograph'
import { KeyExchangeResult, Party } from '../types'

describe('Key exchange', () => {
  const handshakes = {
    alice: Uint8Array.from([
      238, 58, 38, 30, 141, 34, 200, 183, 28, 206, 215, 73, 200, 125, 92, 152,
      101, 211, 214, 130, 33, 158, 114, 200, 43, 30, 212, 100, 176, 149, 15,
      111, 170, 186, 36, 10, 90, 136, 46, 170, 120, 191, 170, 14, 31, 53, 72,
      56, 227, 194, 21, 164, 251, 208, 203, 182, 242, 115, 6, 54, 114, 120, 212,
      226, 72, 160, 235, 116, 148, 31, 19, 62, 52, 116, 28, 172, 227, 191, 95,
      152, 15, 140, 105, 200, 21, 203, 72, 193, 215, 42, 20, 254, 193, 178, 56,
      137
    ]),
    bob: Uint8Array.from([
      40, 96, 87, 46, 204, 210, 12, 62, 80, 86, 55, 252, 191, 201, 183, 188,
      150, 80, 124, 92, 248, 44, 173, 8, 66, 54, 229, 117, 245, 117, 243, 248,
      77, 227, 184, 224, 105, 115, 69, 212, 103, 64, 198, 124, 122, 196, 195,
      215, 250, 95, 169, 218, 185, 119, 150, 206, 130, 255, 243, 124, 48, 52,
      32, 211, 77, 244, 171, 54, 222, 115, 138, 209, 166, 140, 240, 181, 115,
      173, 224, 224, 108, 145, 15, 210, 138, 188, 76, 13, 29, 19, 188, 120, 188,
      109, 89, 34
    ])
  }
  let alice: Party
  let bob: Party
  let a: KeyExchangeResult
  let b: KeyExchangeResult

  beforeAll(async () => {
    await init()
  })

  beforeEach(async () => {
    const keyPairs = {
      alice: {
        identity: {
          publicKey: Uint8Array.from([
            91, 119, 85, 151, 32, 20, 121, 20, 19, 106, 90, 56, 141, 90, 16,
            210, 14, 244, 60, 251, 140, 48, 190, 65, 194, 35, 166, 246, 1, 209,
            4, 33
          ]),
          privateKey: Uint8Array.from([
            43, 6, 246, 172, 137, 170, 33, 12, 118, 177, 111, 60, 19, 37, 65,
            122, 28, 34, 200, 251, 96, 35, 187, 52, 74, 224, 143, 39, 90, 51,
            33, 140
          ])
        },
        ephemeral: {
          publicKey: Uint8Array.from([
            16, 9, 47, 109, 23, 19, 165, 137, 95, 186, 203, 186, 154, 179, 116,
            3, 160, 119, 225, 180, 226, 19, 172, 45, 113, 125, 124, 86, 94, 159,
            161, 119
          ]),
          privateKey: Uint8Array.from([
            171, 243, 152, 144, 76, 145, 84, 13, 243, 173, 102, 244, 84, 223,
            43, 104, 182, 128, 230, 247, 121, 221, 222, 203, 10, 80, 43, 88,
            177, 155, 1, 114
          ])
        }
      },
      bob: {
        identity: {
          publicKey: Uint8Array.from([
            232, 130, 200, 162, 218, 101, 75, 210, 196, 152, 235, 97, 118, 3,
            241, 131, 200, 140, 54, 155, 28, 46, 158, 76, 96, 4, 150, 61, 34,
            13, 133, 138
          ]),
          privateKey: Uint8Array.from([
            243, 11, 156, 139, 99, 129, 212, 8, 60, 53, 111, 123, 69, 158, 83,
            255, 187, 192, 29, 114, 69, 126, 243, 111, 122, 143, 170, 247, 140,
            129, 60, 0
          ])
        },
        ephemeral: {
          publicKey: Uint8Array.from([
            249, 212, 82, 190, 253, 45, 230, 86, 74, 150, 239, 0, 26, 41, 131,
            245, 177, 87, 106, 105, 167, 58, 158, 184, 244, 65, 205, 42, 40, 80,
            134, 52
          ]),
          privateKey: Uint8Array.from([
            252, 67, 175, 250, 230, 100, 145, 82, 139, 125, 242, 5, 40, 8, 155,
            104, 37, 224, 5, 96, 105, 46, 42, 202, 158, 63, 177, 43, 112, 184,
            207, 85
          ])
        }
      }
    }
    alice = createInitiator(
      createSign(keyPairs.alice.identity.privateKey),
      keyPairs.alice.identity.publicKey
    )
    bob = createResponder(
      createSign(keyPairs.bob.identity.privateKey),
      keyPairs.bob.identity.publicKey
    )
    a = await alice.performKeyExchange(
      keyPairs.alice.ephemeral,
      keyPairs.bob.identity.publicKey,
      keyPairs.bob.ephemeral.publicKey
    )
    b = await bob.performKeyExchange(
      keyPairs.bob.ephemeral,
      keyPairs.alice.identity.publicKey,
      keyPairs.alice.ephemeral.publicKey
    )
  })

  it('should allow Alice and Bob to perform a key exchange', () => {
    expect(a.success).toBe(true)
    expect(b.success).toBe(true)
    expect(a.keyExchange.handshake).toEqual(handshakes.alice)
    expect(b.keyExchange.handshake).toEqual(handshakes.bob)
  })
})
