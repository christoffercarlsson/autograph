import Clibautograph
import Foundation

private func createSafetyNumber() -> Bytes {
    createBytes(autograph_safety_number_size())
}

public func authenticate(
    ourIdentityKeyPair: Bytes,
    theirIdentityKey: Bytes
) throws -> Bytes {
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
