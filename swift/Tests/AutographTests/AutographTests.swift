@testable import Autograph
import XCTest

final class AutographTests: XCTestCase {
  func testExample() throws {
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the
    // correct
    // results.
    let autograph = try Autograph()
    let keyPair = try autograph.generateIdentityKeyPair()
    XCTAssertNotNil(keyPair.privateKey)
    XCTAssertNotNil(keyPair.publicKey)
  }
}
