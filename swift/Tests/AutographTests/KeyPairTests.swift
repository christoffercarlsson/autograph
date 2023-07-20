@testable import Autograph
import XCTest

final class KeyPairTests: XCTestCase {
  var autograph: Autograph!

  override func setUp() {
    autograph = Autograph()
  }

  func testGenerateEphemeralKeyPair() {
    let result = autograph.generateEphemeralKeyPair()
    XCTAssertTrue(result.success)
    XCTAssertNotNil(result.keyPair.privateKey)
    XCTAssertNotNil(result.keyPair.publicKey)
    XCTAssertEqual(result.keyPair.privateKey.count, 32)
    XCTAssertEqual(result.keyPair.publicKey.count, 32)
  }

  func testGenerateIdentityKeyPair() {
    let result = autograph.generateIdentityKeyPair()
    XCTAssertTrue(result.success)
    XCTAssertNotNil(result.keyPair.privateKey)
    XCTAssertNotNil(result.keyPair.publicKey)
    XCTAssertEqual(result.keyPair.privateKey.count, 32)
    XCTAssertEqual(result.keyPair.publicKey.count, 32)
  }
}
