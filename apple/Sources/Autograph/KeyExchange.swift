import Clibautograph
import Foundation

public func keyExchange(
    isInitiator: Bool,
    ourIdentityKeyPair: [UInt8],
    ourSessionKeyPair: [UInt8],
    theirIdentityKey: [UInt8],
    theirSessionKey: [UInt8]
) throws -> ([UInt8], [UInt8], [UInt8], [UInt8]) {
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
        ourSessionKeyPair,
        theirIdentityKey,
        theirSessionKey
    )
    if !success {
        throw AutographError.keyExchange
    }
    return (transcript, ourSignature, sendingKey, receivingKey)
}

public func verifyKeyExchange(
    transcript: [UInt8],
    ourIdentityKeyPair: [UInt8],
    theirIdentityKey: [UInt8],
    theirSignature: [UInt8]
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
