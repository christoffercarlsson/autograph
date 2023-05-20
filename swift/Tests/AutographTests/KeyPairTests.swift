@testable import Autograph
import XCTest

final class KeyPairTests: XCTestCase {
  var autograph: Autograph!

  override func setUpWithError() throws {
    autograph = try Autograph()
  }

  func testGenerateEphemeralKeyPair() throws {
    let keyPair = try autograph.generateEphemeralKeyPair()
    XCTAssertNotNil(keyPair.privateKey)
    XCTAssertNotNil(keyPair.publicKey)
    XCTAssertEqual(keyPair.privateKey.count, 32)
    XCTAssertEqual(keyPair.publicKey.count, 32)
  }

  func testGenerateIdentityKeyPair() throws {
    let keyPair = try autograph.generateIdentityKeyPair()
    XCTAssertNotNil(keyPair.privateKey)
    XCTAssertNotNil(keyPair.publicKey)
    XCTAssertEqual(keyPair.privateKey.count, 32)
    XCTAssertEqual(keyPair.publicKey.count, 32)
  }
}
