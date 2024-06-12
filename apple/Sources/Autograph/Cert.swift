import Clibautograph
import Foundation

func createSignature() -> [UInt8] {
    createBytes(autograph_signature_size())
}

public func certify(
    _ ourIdentityKeyPair: [UInt8],
    _ theirIdentityKey: [UInt8],
    _ data: [UInt8]?
) throws -> [UInt8] {
    var signature = createSignature()
    var success = false
    if let data {
        success = autograph_certify(
            &signature,
            ourIdentityKeyPair,
            theirIdentityKey,
            data,
            data.count
        )
    } else {
        success = autograph_certify(
            &signature,
            ourIdentityKeyPair,
            theirIdentityKey,
            createBytes(0),
            0
        )
    }
    if !success {
        throw AutographError.certification
    }
    return signature
}

public func verify(
    _ ownerIdentityKey: [UInt8],
    _ certifierIdentityKey: [UInt8],
    _ signature: [UInt8],
    _ data: [UInt8]?
) -> Bool {
    var verified = false
    if let data {
        verified = autograph_verify(
            ownerIdentityKey,
            certifierIdentityKey,
            signature,
            data,
            data.count
        )
    } else {
        verified = autograph_verify(
            ownerIdentityKey,
            certifierIdentityKey,
            signature,
            createBytes(0),
            0
        )
    }
    return verified
}
