import Clibautograph
import Foundation

public func generateIdentityKeyPair() throws -> Bytes {
    var keyPair = createKeyPair()
    let success = autograph_identity_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}

public func generateSessionKeyPair() throws -> Bytes {
    var keyPair = createKeyPair()
    let success = autograph_session_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}
