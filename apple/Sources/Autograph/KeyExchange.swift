import Clibautograph
import Foundation

public func keyExchange(
    isInitiator: Bool,
    ourIdentityKeyPair: Bytes,
    ourSessionKeyPair: inout Bytes,
    theirIdentityKey: Bytes,
    theirSessionKey: Bytes
) throws -> (Bytes, Bytes, Bytes, Bytes) {
    var transcript = createTranscript()
    var ourSignature = createSignature()
    var sendingKey = createSecretKey()
    var receivingKey = createSecretKey()
    let success = autograph_key_exchange(
        &transcript,
        &ourSignature,
        &sendingKey,
        &receivingKey,
        isInitiator,
        ourIdentityKeyPair,
        &ourSessionKeyPair,
        theirIdentityKey,
        theirSessionKey
    )
    if !success {
        throw AutographError.keyExchange
    }
    return (transcript, ourSignature, sendingKey, receivingKey)
}

public func verifyKeyExchange(
    transcript: Bytes,
    ourIdentityKeyPair: Bytes,
    theirIdentityKey: Bytes,
    theirSignature: Bytes
) throws {
    let verified = autograph_verify_key_exchange(
        transcript,
        ourIdentityKeyPair,
        theirIdentityKey,
        theirSignature
    )
    if !verified {
        throw AutographError.keyExchange
    }
}
