import Clibautograph
import Foundation

func createIdentityKeyPair() -> [UInt8] {
    createBytes(autograph_identity_key_pair_size())
}

func createSessionKeyPair() -> [UInt8] {
    createBytes(autograph_session_key_pair_size())
}

func createIdentityPublicKey() -> [UInt8] {
    createBytes(autograph_identity_public_key_size())
}

func createSessionPublicKey() -> [UInt8] {
    createBytes(autograph_session_public_key_size())
}

public func generateIdentityKeyPair() throws -> [UInt8] {
    var keyPair = createIdentityKeyPair()
    let success = autograph_identity_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}

public func generateSessionKeyPair() throws -> [UInt8] {
    var keyPair = createSessionKeyPair()
    let success = autograph_session_key_pair(&keyPair)
    if !success {
        throw AutographError.keyPair
    }
    return keyPair
}

public func getIdentityPublicKey(_ keyPair: [UInt8]) -> [UInt8] {
    var publicKey = createIdentityPublicKey()
    autograph_get_identity_public_key(&publicKey, keyPair)
    return publicKey
}

public func getSessionPublicKey(_ keyPair: [UInt8]) -> [UInt8] {
    var publicKey = createSessionPublicKey()
    autograph_get_session_public_key(&publicKey, keyPair)
    return publicKey
}

public func getPublicKeys(
    _ identityKeyPair: [UInt8],
    _ sessionKeyPair: [UInt8]
) -> ([UInt8], [UInt8]) {
    let identityKey = getIdentityPublicKey(identityKeyPair)
    let sessionKey = getSessionPublicKey(sessionKeyPair)
    return (identityKey, sessionKey)
}
