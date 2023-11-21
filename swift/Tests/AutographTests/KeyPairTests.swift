import XCTest

@testable import Autograph

final class KeyPairTests: XCTestCase {
  func testGenerateEphemeralKeyPair() throws {
    let keyPair = try Autograph.generateEphemeralKeyPair()
    XCTAssertNotNil(keyPair.privateKey)
    XCTAssertNotNil(keyPair.publicKey)
    XCTAssertEqual(keyPair.privateKey.count, 32)
    XCTAssertEqual(keyPair.publicKey.count, 32)
  }

  func testGenerateIdentityKeyPair() throws {
    let keyPair = try Autograph.generateIdentityKeyPair()
    XCTAssertNotNil(keyPair.privateKey)
    XCTAssertNotNil(keyPair.publicKey)
    XCTAssertEqual(keyPair.privateKey.count, 32)
    XCTAssertEqual(keyPair.publicKey.count, 32)
  }
}
