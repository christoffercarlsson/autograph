import Clibautograph
import Foundation

func createTranscript() -> [UInt8] {
    createBytes(autograph_transcript_size())
}

public func keyExchange(
    _ isInitiator: Bool,
    _ ourIdentityKeyPair: [UInt8],
    _ ourSessionKeyPair: [UInt8],
    _ theirIdentityKey: [UInt8],
    _ theirSessionKey: [UInt8]
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
    _ transcript: [UInt8],
    _ ourIdentityKeyPair: [UInt8],
    _ theirIdentityKey: [UInt8],
    _ theirSignature: [UInt8]
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
