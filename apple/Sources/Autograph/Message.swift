import Clibautograph
import Foundation

private func createCiphertext(_ plaintext: Bytes) -> Bytes {
    let size = autograph_ciphertext_size(plaintext.count)
    return createBytes(size)
}

public func encrypt(
    key: Bytes,
    nonce: inout Bytes,
    plaintext: Bytes
) throws -> (UInt32, Bytes) {
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

private func createPlaintext(_ ciphertext: Bytes) -> Bytes {
    let size = autograph_plaintext_size(ciphertext.count)
    return createBytes(size)
}

private func resizePlaintext(_ plaintext: Bytes, _ size: Int) -> Bytes {
    Array(plaintext[0 ..< size])
}

public func decrypt(
    key: Bytes,
    nonce: inout Bytes,
    skippedIndexes: inout [UInt32],
    ciphertext: Bytes
) throws -> (UInt32, Bytes) {
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
