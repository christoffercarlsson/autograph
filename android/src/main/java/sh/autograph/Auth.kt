package sh.autograph

class Auth {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographSafetyNumberSize(): Int

        private external fun autographAuthenticate(
            safetyNumber: ByteArray,
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
        ): Boolean

        private fun createSafetyNumber(): ByteArray = ByteArray(autographSafetyNumberSize())

        fun authenticate(
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
        ): ByteArray {
            val safetyNumber = createSafetyNumber()
            val success = autographAuthenticate(safetyNumber, ourIdentityKeyPair, theirIdentityKey)
            if (!success) {
                throw RuntimeException("Authentication failed")
            }
            return safetyNumber
        }
    }
}
