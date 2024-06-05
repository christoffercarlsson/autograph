import Clibautograph
import Foundation

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
    key: [UInt8],
    nonce: inout [UInt8],
    plaintext: [UInt8]
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
    key: [UInt8],
    nonce: inout [UInt8],
    skippedIndexes: inout [UInt32],
    ciphertext: [UInt8]
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
        UInt16(skippedIndexes.count),
        ciphertext,
        ciphertext.count
    )
    if !success {
        throw AutographError.decryption
    }
    return (index, resizePlaintext(plaintext, plaintextSize))
}
