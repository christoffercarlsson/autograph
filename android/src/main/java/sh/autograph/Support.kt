package sh.autograph

internal class Support {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographKeyPairSize(): Int

        private external fun autographNonceSize(): Int

        private external fun autographPublicKeySize(): Int

        private external fun autographSafetyNumberSize(): Int

        private external fun autographSecretKeySize(): Int

        private external fun autographSignatureSize(): Int

        private external fun autographTranscriptSize(): Int

        private external fun autographSkippedIndexesCount(): Int

        private external fun autographReady(): Boolean

        fun createKeyPair(): ByteArray = ByteArray(autographKeyPairSize())

        fun createNonce(): ByteArray = ByteArray(autographNonceSize())

        fun createPublicKey(): ByteArray = ByteArray(autographPublicKeySize())

        fun createSafetyNumber(): ByteArray = ByteArray(autographSafetyNumberSize())

        fun createSecretKey(): ByteArray = ByteArray(autographSecretKeySize())

        fun createSignature(): ByteArray = ByteArray(autographSignatureSize())

        fun createTranscript(): ByteArray = ByteArray(autographTranscriptSize())

        fun createSkippedIndexes(): IntArray = IntArray(autographSkippedIndexesCount())

        fun ready() {
            if (!autographReady()) {
                throw RuntimeException("Initialization failed")
            }
        }
    }
}

public fun ready() {
    return Support.ready()
}
