import Clibautograph
import Foundation

public func authenticate(
    ourIdentityKeyPair: [UInt8],
    theirIdentityKey: [UInt8]
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
