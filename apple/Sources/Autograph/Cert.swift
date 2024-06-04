import Clibautograph
import Foundation

public func certify(
    ourIdentityKeyPair: [UInt8],
    theirIdentityKey: [UInt8],
    data: [UInt8]?
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
    ownerIdentityKey: [UInt8],
    certifierIdentityKey: [UInt8],
    signature: [UInt8],
    data: [UInt8]?
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
