import Clibautograph
import Foundation

public func generateIdentityKeyPair() throws -> [UInt8] {
    var keyPair = createKeyPair()
    let success = autograph_identity_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}

public func generateSessionKeyPair() throws -> [UInt8] {
    var keyPair = createKeyPair()
    let success = autograph_session_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}

public func getPublicKey(keyPair: [UInt8]) -> [UInt8] {
    var publicKey = createPublicKey()
    autograph_get_public_key(&publicKey, keyPair)
    return publicKey
}

public func getPublicKeys(
    identityKeyPair: [UInt8],
    sessionKeyPair: [UInt8]
) -> ([UInt8], [UInt8]) {
    let identityKey = getPublicKey(keyPair: identityKeyPair)
    let sessionKey = getPublicKey(keyPair: sessionKeyPair)
    return (identityKey, sessionKey)
}
