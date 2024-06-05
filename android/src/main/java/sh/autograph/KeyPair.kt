package sh.autograph

internal class KeyPair {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographIdentityKeyPair(keyPair: ByteArray): Boolean

        private external fun autographSessionKeyPair(keyPair: ByteArray): Boolean

        private external fun autographGetPublicKey(
            publicKey: ByteArray,
            keyPair: ByteArray,
        )

        fun generateIdentityKeyPair(): ByteArray {
            val keyPair = Support.createKeyPair()
            val success = autographIdentityKeyPair(keyPair)
            if (!success) {
                throw RuntimeException("Key generation failed")
            }
            return keyPair
        }

        fun generateSessionKeyPair(): ByteArray {
            val keyPair = Support.createKeyPair()
            val success = autographSessionKeyPair(keyPair)
            if (!success) {
                throw RuntimeException("Key generation failed")
            }
            return keyPair
        }

        fun getPublicKey(keyPair: ByteArray): ByteArray {
            val publicKey = Support.createPublicKey()
            autographGetPublicKey(publicKey, keyPair)
            return publicKey
        }

        fun getPublicKeys(
            identityKeyPair: ByteArray,
            sessionKeyPair: ByteArray,
        ): Pair<ByteArray, ByteArray> {
            val identityKey = getPublicKey(identityKeyPair)
            val sessionKey = getPublicKey(sessionKeyPair)
            return Pair(identityKey, sessionKey)
        }
    }
}

public fun generateIdentityKeyPair(): ByteArray {
    return KeyPair.generateIdentityKeyPair()
}

public fun generateSessionKeyPair(): ByteArray {
    return KeyPair.generateSessionKeyPair()
}

public fun getPublicKey(keyPair: ByteArray): ByteArray {
    return KeyPair.getPublicKey(keyPair)
}

public fun getPublicKeys(
    identityKeyPair: ByteArray,
    sessionKeyPair: ByteArray,
): Pair<ByteArray, ByteArray> {
    return KeyPair.getPublicKeys(identityKeyPair, sessionKeyPair)
}
