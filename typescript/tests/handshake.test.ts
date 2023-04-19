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
  const handshakes = {
    alice: createFrom([
      136, 244, 193, 52, 138, 176, 191, 106, 118, 164, 139, 44, 234, 218, 175,
      211, 223, 23, 166, 177, 112, 29, 82, 218, 205, 50, 212, 122, 12, 9, 168,
      44, 53, 180, 26, 247, 190, 70, 31, 95, 206, 26, 205, 87, 35, 181, 209,
      209, 107, 162, 77, 57, 213, 145, 187, 123, 229, 177, 14, 129, 0, 2, 58,
      220, 148, 199, 150, 132, 114, 201, 47, 45, 128, 173, 105, 60, 217, 211, 1,
      71
    ]),
    bob: createFrom([
      168, 212, 240, 194, 121, 97, 36, 79, 199, 83, 26, 4, 222, 250, 237, 123,
      132, 38, 250, 105, 93, 24, 104, 237, 134, 190, 164, 48, 9, 79, 50, 171,
      80, 162, 96, 59, 216, 79, 93, 254, 6, 147, 113, 134, 178, 154, 156, 218,
      124, 229, 93, 27, 15, 56, 245, 4, 178, 250, 229, 127, 225, 59, 33, 127,
      207, 12, 72, 168, 134, 253, 16, 2, 152, 3, 109, 103, 133, 13, 132, 64
    ])
  }
  let alice: Party
  let bob: Party

  beforeEach(async () => {
    alice = await createInitiator(
      keyPairs.alice.identity,
      keyPairs.alice.ephemeral
    )
    bob = await createResponder(keyPairs.bob.identity, keyPairs.bob.ephemeral)
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
    expect(a.handshake).toEqual(handshakes.alice)
    expect(b.handshake).toEqual(handshakes.bob)
  })
})
