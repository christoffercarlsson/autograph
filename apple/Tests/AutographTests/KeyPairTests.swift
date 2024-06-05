import XCTest

@testable import Autograph

final class KeyPairTests: XCTestCase {
    override func setUpWithError() throws {
        try Autograph.ready()
    }

    func testGenerateIdentityKeyPair() throws {
        let emptyKeyPair = [UInt8](repeating: 0, count: 64)
        let keyPair = try Autograph.generateIdentityKeyPair()
        XCTAssertEqual(keyPair.count, 64)
        XCTAssertNotEqual(keyPair, emptyKeyPair)
    }

    func testGenerateSessionKeyPair() throws {
        let emptyKeyPair = [UInt8](repeating: 0, count: 64)
        let keyPair = try Autograph.generateSessionKeyPair()
        XCTAssertEqual(keyPair.count, 64)
        XCTAssertNotEqual(keyPair, emptyKeyPair)
    }
}
