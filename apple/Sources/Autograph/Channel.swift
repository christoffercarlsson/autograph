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
    var skippedIndexes: [UInt32]

    public init(
        ourIdentityKeyPair: [UInt8],
        ourSessionKeyPair: [UInt8],
        theirIdentityKey: [UInt8],
        theirSessionKey: [UInt8]
    ) {
        self.ourIdentityKeyPair = createKeyPair()
        self.ourSessionKeyPair = createKeyPair()
        self.theirIdentityKey = createPublicKey()
        self.theirSessionKey = createPublicKey()
        transcript = createTranscript()
        sendingKey = createSecretKey()
        receivingKey = createSecretKey()
        sendingNonce = createNonce()
        receivingNonce = createNonce()
        skippedIndexes = createSkippedIndexes()
        autograph_use_key_pairs(
            &self.ourIdentityKeyPair,
            &self.ourSessionKeyPair,
            ourIdentityKeyPair,
            ourSessionKeyPair
        )
        autograph_use_public_keys(
            &self.theirIdentityKey,
            &self.theirSessionKey,
            theirIdentityKey,
            theirSessionKey
        )
    }

    public func authenticate() throws -> [UInt8] {
        try Autograph.authenticate(
            ourIdentityKeyPair: ourIdentityKeyPair,
            theirIdentityKey: theirIdentityKey
        )
    }

    public func certify(data: [UInt8]?) throws -> [UInt8] {
        try Autograph.certify(
            ourIdentityKeyPair: ourIdentityKeyPair,
            theirIdentityKey: theirIdentityKey,
            data: data
        )
    }

    public func verify(
        certifierIdentityKey: [UInt8],
        signature: [UInt8],
        data: [UInt8]?
    ) -> Bool {
        Autograph.verify(
            ownerIdentityKey: theirIdentityKey,
            certifierIdentityKey: certifierIdentityKey,
            signature: signature,
            data: data
        )
    }

    public func keyExchange(isInitiator: Bool) throws -> [UInt8] {
        let (
            transcript,
            ourSignature,
            sendingKey,
            receivingKey
        ) = try Autograph.keyExchange(
            isInitiator: isInitiator,
            ourIdentityKeyPair: ourIdentityKeyPair,
            ourSessionKeyPair: ourSessionKeyPair,
            theirIdentityKey: theirIdentityKey,
            theirSessionKey: theirSessionKey
        )
        self.transcript = transcript
        self.sendingKey = sendingKey
        self.receivingKey = receivingKey
        return ourSignature
    }

    public func verifyKeyExchange(theirSignature: [UInt8]) throws {
        try Autograph.verifyKeyExchange(
            transcript: transcript,
            ourIdentityKeyPair: ourIdentityKeyPair,
            theirIdentityKey: theirIdentityKey,
            theirSignature: theirSignature
        )
    }

    public func encrypt(plaintext: [UInt8]) throws -> (UInt32, [UInt8]) {
        try Autograph.encrypt(
            key: sendingKey,
            nonce: &sendingNonce,
            plaintext: plaintext
        )
    }

    public func decrypt(ciphertext: [UInt8]) throws -> (UInt32, [UInt8]) {
        try Autograph.decrypt(
            key: receivingKey,
            nonce: &receivingNonce,
            skippedIndexes: &skippedIndexes,
            ciphertext: ciphertext
        )
    }
}
