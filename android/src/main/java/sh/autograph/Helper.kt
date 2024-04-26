package sh.autograph

internal class Helper {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographKeyPairSize(): Int

        private external fun autographNonceSize(): Int

        private external fun autographPublicKeySize(): Int

        private external fun autographSecretKeySize(): Int

        private external fun autographSignatureSize(): Int

        private external fun autographTranscriptSize(): Int

        private external fun autographZeroize(data: ByteArray)

        private external fun autographIsZero(data: ByteArray): Boolean

        fun createKeyPair(): ByteArray = ByteArray(autographKeyPairSize())

        fun createNonce(): ByteArray = ByteArray(autographNonceSize())

        fun createPublicKey(): ByteArray = ByteArray(autographPublicKeySize())

        fun createSecretKey(): ByteArray = ByteArray(autographSecretKeySize())

        fun createSignature(): ByteArray = ByteArray(autographSignatureSize())

        fun createTranscript(): ByteArray = ByteArray(autographTranscriptSize())

        fun zeroize(data: ByteArray) {
            autographZeroize(data)
        }

        fun isZero(data: ByteArray): Boolean {
            return autographIsZero(data)
        }
    }
}
