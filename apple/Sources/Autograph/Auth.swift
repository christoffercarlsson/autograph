import Clibautograph
import Foundation

func createSafetyNumber() -> [UInt8] {
    createBytes(autograph_safety_number_size())
}

public func authenticate(
    _ ourIdentityKeyPair: [UInt8],
    _ theirIdentityKey: [UInt8]
) throws -> [UInt8] {
    var safetyNumber = createSafetyNumber()
    let success = autograph_authenticate(
        &safetyNumber,
        ourIdentityKeyPair,
        theirIdentityKey
    )
    if !success {
        throw AutographError.authentication
    }
    return safetyNumber
}
