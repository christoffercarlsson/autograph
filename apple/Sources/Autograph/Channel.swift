import Clibautograph
import Foundation

public class Channel {
    var ourIdentityKeyPair: [UInt8]
    var ourSessionKeyPair: [UInt8]
    var theirIdentityKey: [UInt8]
    var theirSessionKey: [UInt8]
    var transcript: [UInt8]
    var sendingKey: [UInt8]
    var receivingKey: [UInt8]
    var sendingNonce: [UInt8]
    var receivingNonce: [UInt8]
    var skippedIndexes: [UInt8]

    public init() {
        ourIdentityKeyPair = createIdentityKeyPair()
        ourSessionKeyPair = createSessionKeyPair()
        theirIdentityKey = createIdentityPublicKey()
        theirSessionKey = createSessionPublicKey()
        transcript = createTranscript()
        sendingKey = createSecretKey()
        receivingKey = createSecretKey()
        sendingNonce = createNonce()
        receivingNonce = createNonce()
        skippedIndexes = createSkippedIndexes(nil)
    }

    public func useKeyPairs(
        _ ourIdentityKeyPair: [UInt8],
        _ ourSessionKeyPair: [UInt8]
    ) -> ([UInt8], [UInt8]) {
        autograph_use_key_pairs(
            &self.ourIdentityKeyPair,
            &self.ourSessionKeyPair,
            ourIdentityKeyPair,
            ourSessionKeyPair
        )
        return getPublicKeys(ourIdentityKeyPair, ourSessionKeyPair)
    }

    public func usePublicKeys(
        _ theirIdentityKey: [UInt8],
        _ theirSessionKey: [UInt8]
    ) {
        autograph_use_public_keys(
            &self.theirIdentityKey,
            &self.theirSessionKey,
            theirIdentityKey,
            theirSessionKey
        )
    }

    public func authenticate(
        _ ourId: [UInt8],
        _ theirId: [UInt8]
    ) throws -> [UInt8] {
        try Autograph.authenticate(
            ourIdentityKeyPair,
            ourId,
            theirIdentityKey,
            theirId
        )
    }

    public func certify(_ data: [UInt8]?) throws -> [UInt8] {
        try Autograph.certify(
            ourIdentityKeyPair,
            theirIdentityKey,
            data
        )
    }

    public func verify(
        _ certifierIdentityKey: [UInt8],
        _ signature: [UInt8],
        _ data: [UInt8]?
    ) -> Bool {
        Autograph.verify(
            theirIdentityKey,
            certifierIdentityKey,
            signature,
            data
        )
    }

    public func keyExchange(_ isInitiator: Bool) throws -> [UInt8] {
        let (
            transcript,
            ourSignature,
            sendingKey,
            receivingKey
        ) = try Autograph.keyExchange(
            isInitiator,
            ourIdentityKeyPair,
            ourSessionKeyPair,
            theirIdentityKey,
            theirSessionKey
        )
        self.transcript = transcript
        self.sendingKey = sendingKey
        self.receivingKey = receivingKey
        return ourSignature
    }

    public func verifyKeyExchange(_ theirSignature: [UInt8]) throws {
        try Autograph.verifyKeyExchange(
            transcript,
            ourIdentityKeyPair,
            theirIdentityKey,
            theirSignature
        )
    }

    public func encrypt(_ plaintext: [UInt8]) throws -> (UInt32, [UInt8]) {
        try Autograph.encrypt(
            sendingKey,
            &sendingNonce,
            plaintext
        )
    }

    public func decrypt(_ ciphertext: [UInt8]) throws -> (UInt32, [UInt8]) {
        try Autograph.decrypt(
            receivingKey,
            &receivingNonce,
            &skippedIndexes,
            ciphertext
        )
    }
}
