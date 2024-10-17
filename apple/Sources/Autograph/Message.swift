import Clibautograph
import Foundation

func createSecretKey() -> [UInt8] {
    createBytes(autograph_secret_key_size())
}

public func generateSecretKey() throws -> [UInt8] {
    var key = createSecretKey()
    let success = autograph_generate_secret_key(&key)
    if !success {
        throw AutographError.keyGeneration
    }
    return key
}

public func createNonce() -> [UInt8] {
    createBytes(autograph_nonce_size())
}

public func createSkippedIndexes(_ count: UInt16?) -> [UInt8] {
    createBytes(autograph_skipped_indexes_size(count ?? 0))
}

private func createCiphertext(_ plaintext: [UInt8]) -> [UInt8] {
    let size = autograph_ciphertext_size(plaintext.count)
    return createBytes(size)
}

private func createPlaintext(_ ciphertext: [UInt8]) -> [UInt8] {
    let size = autograph_plaintext_size(ciphertext.count)
    return createBytes(size)
}

private func resizePlaintext(_ plaintext: [UInt8], _ size: Int) -> [UInt8] {
    Array(plaintext[0 ..< size])
}

public func encrypt(
    _ key: [UInt8],
    _ nonce: inout [UInt8],
    _ plaintext: [UInt8]
) throws -> (UInt32, [UInt8]) {
    var ciphertext = createCiphertext(plaintext)
    var index: UInt32 = 0
    let success = autograph_encrypt(
        &index,
        &ciphertext,
        key,
        &nonce,
        plaintext,
        plaintext.count
    )
    if !success {
        throw AutographError.encryption
    }
    return (index, ciphertext)
}

public func decrypt(
    _ key: [UInt8],
    _ nonce: inout [UInt8],
    _ skippedIndexes: inout [UInt8],
    _ ciphertext: [UInt8]
) throws -> (UInt32, [UInt8]) {
    var plaintext = createPlaintext(ciphertext)
    var index: UInt32 = 0
    var plaintextSize = 0
    let success = autograph_decrypt(
        &index,
        &plaintext,
        &plaintextSize,
        key,
        &nonce,
        &skippedIndexes,
        skippedIndexes.count,
        ciphertext,
        ciphertext.count
    )
    if !success {
        throw AutographError.decryption
    }
    return (index, resizePlaintext(plaintext, plaintextSize))
}
