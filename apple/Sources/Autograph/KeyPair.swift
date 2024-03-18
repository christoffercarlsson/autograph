import Clibautograph
import Foundation

private func createKeyPair() -> Bytes {
    createBytes(autograph_key_pair_size())
}

public func generateIdentityKeyPair() throws -> Bytes {
    var keyPair = createKeyPair()
    let success = autograph_identity_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}

public func generateKeyPair() throws -> Bytes {
    var keyPair = createKeyPair()
    let success = autograph_ephemeral_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}
