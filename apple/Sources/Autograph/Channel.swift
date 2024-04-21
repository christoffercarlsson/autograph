import Clibautograph
import Foundation

private func createSkippedIndexes(_ count: UInt16?) -> [UInt32] {
    [UInt32](repeating: 0, count: Int(count ?? 100))
}

public class Channel {
    var ourIdentityKeyPair: Bytes
    var ourSessionKeyPair: Bytes
    var theirIdentityKey: Bytes
    var theirSessionKey: Bytes
    var transcript: Bytes
    var sendingKey: Bytes
    var receivingKey: Bytes
    var sendingNonce: Bytes
    var receivingNonce: Bytes
    var skippedIndexes: [UInt32]
    var established: Bool

    public init(skippedIndexesCount: UInt16?) {
        ourIdentityKeyPair = createKeyPair()
        ourSessionKeyPair = createKeyPair()
        theirIdentityKey = createPublicKey()
        theirSessionKey = createPublicKey()
        transcript = createTranscript()
        sendingKey = createSecretKey()
        receivingKey = createSecretKey()
        sendingNonce = createNonce()
        receivingNonce = createNonce()
        skippedIndexes = createSkippedIndexes(skippedIndexesCount)
        established = false
    }

    public func isEstablished() -> Bool {
        established
    }

    public func useKeyPairs(
        ourIdentityKeyPair: Bytes,
        ourSessionKeyPair: inout Bytes
    ) throws -> (Bytes, Bytes) {
        established = false
        var identityKey = createPublicKey()
        var sessionKey = createPublicKey()
        let ready = autograph_use_key_pairs(
            &identityKey,
            &sessionKey,
            &self.ourIdentityKeyPair,
            &self.ourSessionKeyPair,
            ourIdentityKeyPair,
            &ourSessionKeyPair
        )
        if !ready {
            throw AutographError.initialization
        }
        return (identityKey, sessionKey)
    }

    public func usePublicKeys(theirIdentityKey: Bytes, theirSessionKey: Bytes) {
        established = false
        autograph_use_public_keys(
            &self.theirIdentityKey,
            &self.theirSessionKey,
            theirIdentityKey,
            theirSessionKey
        )
    }

    public func authenticate() throws -> Bytes {
        try Autograph.authenticate(ourIdentityKeyPair: ourIdentityKeyPair, theirIdentityKey: theirIdentityKey)
    }

    public func certify(data: Bytes?) throws -> Bytes {
        try Autograph.certify(ourIdentityKeyPair: ourIdentityKeyPair, theirIdentityKey: theirIdentityKey, data: data)
    }

    public func verify(
        certifierIdentityKey: Bytes,
        signature: Bytes,
        data: Bytes?
    ) -> Bool {
        Autograph.verify(ownerIdentityKey: theirIdentityKey, certifierIdentityKey: certifierIdentityKey, signature: signature, data: data)
    }

    public func keyExchange(isInitiator: Bool) throws -> Bytes {
        established = false
        let (
            transcript,
            ourSignature,
            sendingKey,
            receivingKey
        ) = try Autograph.keyExchange(
            isInitiator: isInitiator,
            ourIdentityKeyPair: ourIdentityKeyPair,
            ourSessionKeyPair: &ourSessionKeyPair,
            theirIdentityKey: theirIdentityKey,
            theirSessionKey: theirSessionKey
        )
        self.transcript = transcript
        self.sendingKey = sendingKey
        self.receivingKey = receivingKey
        return ourSignature
    }

    public func verifyKeyExchange(theirSignature: Bytes) throws {
        try Autograph.verifyKeyExchange(
            transcript: transcript,
            ourIdentityKeyPair: ourIdentityKeyPair,
            theirIdentityKey: theirIdentityKey,
            theirSignature: theirSignature
        )
        established = true
        zeroize(data: &sendingNonce)
        zeroize(data: &receivingNonce)
        skippedIndexes = Array(repeating: 0, count: skippedIndexes.count)
    }

    public func encrypt(plaintext: Bytes) throws -> (UInt32, Bytes) {
        if established {
            return try Autograph.encrypt(key: sendingKey, nonce: &sendingNonce, plaintext: plaintext)
        } else {
            throw AutographError.encryption
        }
    }

    public func decrypt(ciphertext: Bytes) throws -> (UInt32, Bytes) {
        if established {
            return try Autograph.decrypt(
                key: receivingKey,
                nonce: &receivingNonce,
                skippedIndexes: &skippedIndexes,
                ciphertext: ciphertext
            )
        } else {
            throw AutographError.decryption
        }
    }

    public func close() {
        established = false
        zeroize(data: &ourIdentityKeyPair)
        zeroize(data: &ourSessionKeyPair)
        zeroize(data: &sendingKey)
        zeroize(data: &receivingKey)
        zeroize(data: &sendingNonce)
        zeroize(data: &receivingNonce)
        skippedIndexes = Array(repeating: 0, count: skippedIndexes.count)
    }
}
