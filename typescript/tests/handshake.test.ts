import { createFrom } from 'stedy/bytes'
import { createInitiator, createResponder } from '../src/autograph'
import { Party } from '../types'

describe('Handshake', () => {
  const keyPairs = {
    alice: {
      identity: {
        publicKey: createFrom([
          91, 119, 85, 151, 32, 20, 121, 20, 19, 106, 90, 56, 141, 90, 16, 210,
          14, 244, 60, 251, 140, 48, 190, 65, 194, 35, 166, 246, 1, 209, 4, 33
        ]),
        privateKey: createFrom([
          43, 6, 246, 172, 137, 170, 33, 12, 118, 177, 111, 60, 19, 37, 65, 122,
          28, 34, 200, 251, 96, 35, 187, 52, 74, 224, 143, 39, 90, 51, 33, 140
        ])
      },
      ephemeral: {
        publicKey: createFrom([
          16, 9, 47, 109, 23, 19, 165, 137, 95, 186, 203, 186, 154, 179, 116, 3,
          160, 119, 225, 180, 226, 19, 172, 45, 113, 125, 124, 86, 94, 159, 161,
          119
        ]),
        privateKey: createFrom([
          171, 243, 152, 144, 76, 145, 84, 13, 243, 173, 102, 244, 84, 223, 43,
          104, 182, 128, 230, 247, 121, 221, 222, 203, 10, 80, 43, 88, 177, 155,
          1, 114
        ])
      }
    },
    bob: {
      identity: {
        publicKey: createFrom([
          232, 130, 200, 162, 218, 101, 75, 210, 196, 152, 235, 97, 118, 3, 241,
          131, 200, 140, 54, 155, 28, 46, 158, 76, 96, 4, 150, 61, 34, 13, 133,
          138
        ]),
        privateKey: createFrom([
          243, 11, 156, 139, 99, 129, 212, 8, 60, 53, 111, 123, 69, 158, 83,
          255, 187, 192, 29, 114, 69, 126, 243, 111, 122, 143, 170, 247, 140,
          129, 60, 0
        ])
      },
      ephemeral: {
        publicKey: createFrom([
          249, 212, 82, 190, 253, 45, 230, 86, 74, 150, 239, 0, 26, 41, 131,
          245, 177, 87, 106, 105, 167, 58, 158, 184, 244, 65, 205, 42, 40, 80,
          134, 52
        ]),
        privateKey: createFrom([
          252, 67, 175, 250, 230, 100, 145, 82, 139, 125, 242, 5, 40, 8, 155,
          104, 37, 224, 5, 96, 105, 46, 42, 202, 158, 63, 177, 43, 112, 184,
          207, 85
        ])
      }
    }
  }
  const messages = {
    alice: createFrom([
      157, 61, 99, 76, 123, 207, 247, 194, 32, 224, 244, 148, 38, 107, 158, 13,
      66, 237, 6, 32, 9, 98, 120, 172, 63, 45, 144, 194, 251, 88, 48, 88, 129,
      3, 192, 127, 172, 229, 66, 244, 122, 42, 217, 146, 47, 131, 64, 13, 107,
      18, 173, 108, 41, 120, 116, 34, 129, 5, 243, 248, 99, 109, 135, 104, 46,
      19, 83, 20, 244, 153, 122, 18, 90, 151, 188, 95, 57, 79, 224, 173
    ]),
    bob: createFrom([
      10, 63, 180, 74, 97, 108, 26, 163, 144, 152, 159, 14, 195, 134, 181, 244,
      55, 32, 29, 68, 195, 2, 99, 176, 3, 188, 77, 223, 82, 222, 85, 33, 164,
      83, 212, 5, 137, 216, 156, 53, 173, 72, 8, 43, 132, 54, 25, 6, 55, 62,
      116, 75, 206, 125, 216, 8, 52, 89, 117, 36, 65, 68, 225, 150, 17, 45, 160,
      163, 56, 102, 169, 218, 53, 41, 248, 194, 14, 51, 103, 188
    ])
  }
  let alice: Party
  let bob: Party

  beforeEach(() => {
    alice = createInitiator(keyPairs.alice.identity, keyPairs.alice.ephemeral)
    bob = createResponder(keyPairs.bob.identity, keyPairs.bob.ephemeral)
  })

  it('should allow Alice and Bob to perform a handshake', async () => {
    const b = await bob.performHandshake(
      keyPairs.alice.identity.publicKey,
      keyPairs.alice.ephemeral.publicKey
    )
    const a = await alice.performHandshake(
      keyPairs.bob.identity.publicKey,
      keyPairs.bob.ephemeral.publicKey
    )
    expect(a.success).toBe(true)
    expect(b.success).toBe(true)
    expect(a.handshake.message).toEqual(messages.alice)
    expect(b.handshake.message).toEqual(messages.bob)
  })
})
