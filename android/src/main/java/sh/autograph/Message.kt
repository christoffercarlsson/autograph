package sh.autograph

internal class Message {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographCiphertextSize(plaintextSize: Int): Int

        private external fun autographPlaintextSize(ciphertextSize: Int): Int

        private external fun autographEncrypt(
            index: IntArray,
            ciphertext: ByteArray,
            key: ByteArray,
            nonce: ByteArray,
            plaintext: ByteArray,
        ): Boolean

        private external fun autographDecrypt(
            index: IntArray,
            plaintext: ByteArray,
            plaintextSize: IntArray,
            key: ByteArray,
            nonce: ByteArray,
            skippedIndexes: IntArray,
            ciphertext: ByteArray,
        ): Boolean

        private fun createCiphertext(plaintext: ByteArray): ByteArray {
            val size = autographCiphertextSize(plaintext.size)
            return ByteArray(size)
        }

        private fun createPlaintext(ciphertext: ByteArray): ByteArray {
            val size = autographPlaintextSize(ciphertext.size)
            return ByteArray(size)
        }

        fun encrypt(
            key: ByteArray,
            nonce: ByteArray,
            plaintext: ByteArray,
        ): Pair<Int, ByteArray> {
            val index = IntArray(1)
            val ciphertext = createCiphertext(plaintext)
            val success = autographEncrypt(index, ciphertext, key, nonce, plaintext)
            if (!success) {
                throw RuntimeException("Encryption failed")
            }
            return Pair(index[0], ciphertext)
        }

        fun decrypt(
            key: ByteArray,
            nonce: ByteArray,
            skippedIndexes: IntArray,
            ciphertext: ByteArray,
        ): Pair<Int, ByteArray> {
            val index = IntArray(1)
            val plaintextSize = IntArray(1)
            val plaintext = createPlaintext(ciphertext)
            val success = autographDecrypt(index, plaintext, plaintextSize, key, nonce, skippedIndexes, ciphertext)
            if (!success) {
                throw RuntimeException("Decryption failed")
            }
            return Pair(index[0], plaintext.copyOf(plaintextSize[0]))
        }
    }
}

public fun encrypt(
    key: ByteArray,
    nonce: ByteArray,
    plaintext: ByteArray,
): Pair<Int, ByteArray> {
    return Message.encrypt(key, nonce, plaintext)
}

public fun decrypt(
    key: ByteArray,
    nonce: ByteArray,
    skippedIndexes: IntArray,
    ciphertext: ByteArray,
): Pair<Int, ByteArray> {
    return Message.decrypt(key, nonce, skippedIndexes, ciphertext)
}
