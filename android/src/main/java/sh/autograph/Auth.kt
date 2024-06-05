package sh.autograph

internal class Auth {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographAuthenticate(
            safetyNumber: ByteArray,
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
        ): Boolean

        fun authenticate(
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
        ): ByteArray {
            val safetyNumber = Support.createSafetyNumber()
            val success = autographAuthenticate(safetyNumber, ourIdentityKeyPair, theirIdentityKey)
            if (!success) {
                throw RuntimeException("Authentication failed")
            }
            return safetyNumber
        }
    }
}

public fun authenticate(
    ourIdentityKeyPair: ByteArray,
    theirIdentityKey: ByteArray,
): ByteArray {
    return Auth.authenticate(ourIdentityKeyPair, theirIdentityKey)
}
