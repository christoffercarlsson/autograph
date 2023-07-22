@testable import Autograph
import XCTest

final class SafetyNumberTests: XCTestCase {
  let aliceIdentityKeyPair = KeyPair(privateKey: [
    43,
    6,
    246,
    172,
    137,
    170,
    33,
    12,
    118,
    177,
    111,
    60,
    19,
    37,
    65,
    122,
    28,
    34,
    200,
    251,
    96,
    35,
    187,
    52,
    74,
    224,
    143,
    39,
    90,
    51,
    33,
    140,
  ], publicKey: [
    91,
    119,
    85,
    151,
    32,
    20,
    121,
    20,
    19,
    106,
    90,
    56,
    141,
    90,
    16,
    210,
    14,
    244,
    60,
    251,
    140,
    48,
    190,
    65,
    194,
    35,
    166,
    246,
    1,
    209,
    4,
    33,
  ])
  let aliceEphemeralKeyPair = KeyPair(
    privateKey: [171, 243, 152, 144, 76, 145, 84, 13, 243, 173, 102,
                 244, 84, 223, 43, 104, 182, 128, 230, 247, 121, 221,
                 222, 203, 10, 80, 43, 88, 177, 155, 1, 114],
    publicKey: [16, 9, 47, 109, 23, 19, 165, 137, 95, 186, 203,
                186, 154, 179, 116, 3, 160, 119, 225, 180, 226, 19,
                172, 45, 113, 125, 124, 86, 94, 159, 161, 119]
  )
  let bobIdentityKeyPair = KeyPair(
    privateKey: [243, 11, 156, 139, 99, 129, 212, 8, 60, 53, 111, 123, 69, 158,
                 83, 255,
                 187, 192, 29, 114, 69, 126, 243, 111, 122, 143, 170, 247, 140,
                 129, 60,
                 0],
    publicKey: [
      232,
      130,
      200,
      162,
      218,
      101,
      75,
      210,
      196,
      152,
      235,
      97,
      118,
      3,
      241,
      131,
      200,
      140,
      54,
      155,
      28,
      46,
      158,
      76,
      96,
      4,
      150,
      61,
      34,
      13,
      133,
      138,
    ]
  )
  let bobEphemeralKeyPair = KeyPair(
    privateKey: [252, 67, 175, 250, 230, 100, 145, 82, 139, 125, 242,
                 5, 40, 8, 155, 104, 37, 224, 5, 96, 105, 46,
                 42, 202, 158, 63, 177, 43, 112, 184, 207, 85],
    publicKey: [249, 212, 82, 190, 253, 45, 230, 86, 74, 150, 239,
                0, 26, 41, 131, 245, 177, 87, 106, 105, 167, 58,
                158, 184, 244, 65, 205, 42, 40, 80, 134, 52]
  )
  let safetyNumber: Bytes = [
    52,
    52,
    57,
    52,
    50,
    50,
    53,
    55,
    54,
    50,
    48,
    53,
    51,
    51,
    49,
    55,
    56,
    54,
    48,
    50,
    55,
    53,
    56,
    48,
    54,
    52,
    56,
    52,
    53,
    49,
    53,
    55,
    50,
    49,
    50,
    54,
    49,
    50,
    50,
    49,
    57,
    52,
    53,
    57,
    52,
    50,
    55,
    54,
    49,
    49,
    54,
    49,
    57,
    50,
    52,
    53,
    52,
    57,
    50,
    54,
  ]
  var autograph: Autograph!
  var alice: Party!
  var bob: Party!

  override func setUp() {
    autograph = Autograph()
    alice = autograph.createInitiator(
      identityKeyPair: aliceIdentityKeyPair
    )
    bob = autograph.createResponder(
      identityKeyPair: bobIdentityKeyPair
    )
  }

  func testCalculateSafetyNumber() {
    let a = alice.calculateSafetyNumber(bobIdentityKeyPair.publicKey)
    let b = bob.calculateSafetyNumber(aliceIdentityKeyPair.publicKey)
    XCTAssertTrue(a.success)
    XCTAssertTrue(b.success)
    XCTAssertEqual(a.safetyNumber, safetyNumber)
    XCTAssertEqual(b.safetyNumber, safetyNumber)
  }
}
