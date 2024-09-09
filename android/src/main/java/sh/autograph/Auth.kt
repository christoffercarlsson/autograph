package sh.autograph

internal class Auth {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographSafetyNumberSize(): Int

        private external fun autographAuthenticate(
            safetyNumber: ByteArray,
            ourIdentityKeyPair: ByteArray,
            ourId: ByteArray,
            theirIdentityKey: ByteArray,
            theirId: ByteArray,
        ): Boolean

        fun createSafetyNumber(): ByteArray = ByteArray(autographSafetyNumberSize())

        fun authenticate(
            ourIdentityKeyPair: ByteArray,
            ourId: ByteArray,
            theirIdentityKey: ByteArray,
            theirId: ByteArray,
        ): ByteArray {
            val safetyNumber = createSafetyNumber()
            val success = autographAuthenticate(safetyNumber, ourIdentityKeyPair, ourId, theirIdentityKey, theirId)
            if (!success) {
                throw RuntimeException("Authentication failed")
            }
            return safetyNumber
        }
    }
}

public fun authenticate(
    ourIdentityKeyPair: ByteArray,
    ourId: ByteArray,
    theirIdentityKey: ByteArray,
    theirId: ByteArray,
): ByteArray {
    return Auth.authenticate(ourIdentityKeyPair, ourId, theirIdentityKey, theirId)
}
