package sh.autograph

internal class KeyPair {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographIdentityKeyPairSize(): Int

        private external fun autographSessionKeyPairSize(): Int

        private external fun autographIdentityPublicKeySize(): Int

        private external fun autographSessionPublicKeySize(): Int

        private external fun autographIdentityKeyPair(keyPair: ByteArray): Boolean

        private external fun autographSessionKeyPair(keyPair: ByteArray): Boolean

        private external fun autographGetIdentityPublicKey(
            publicKey: ByteArray,
            keyPair: ByteArray,
        )

        private external fun autographGetSessionPublicKey(
            publicKey: ByteArray,
            keyPair: ByteArray,
        )

        fun createIdentityKeyPair(): ByteArray = ByteArray(autographIdentityKeyPairSize())

        fun createSessionKeyPair(): ByteArray = ByteArray(autographSessionKeyPairSize())

        fun createIdentityPublicKey(): ByteArray = ByteArray(autographIdentityPublicKeySize())

        fun createSessionPublicKey(): ByteArray = ByteArray(autographSessionPublicKeySize())

        fun generateIdentityKeyPair(): ByteArray {
            val keyPair = createIdentityKeyPair()
            val success = autographIdentityKeyPair(keyPair)
            if (!success) {
                throw RuntimeException("Key generation failed")
            }
            return keyPair
        }

        fun generateSessionKeyPair(): ByteArray {
            val keyPair = createSessionKeyPair()
            val success = autographSessionKeyPair(keyPair)
            if (!success) {
                throw RuntimeException("Key generation failed")
            }
            return keyPair
        }

        fun getIdentityPublicKey(keyPair: ByteArray): ByteArray {
            val publicKey = createIdentityPublicKey()
            autographGetIdentityPublicKey(publicKey, keyPair)
            return publicKey
        }

        fun getSessionPublicKey(keyPair: ByteArray): ByteArray {
            val publicKey = createSessionPublicKey()
            autographGetSessionPublicKey(publicKey, keyPair)
            return publicKey
        }

        fun getPublicKeys(
            identityKeyPair: ByteArray,
            sessionKeyPair: ByteArray,
        ): Pair<ByteArray, ByteArray> {
            val identityKey = getIdentityPublicKey(identityKeyPair)
            val sessionKey = getSessionPublicKey(sessionKeyPair)
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

public fun getIdentityPublicKey(keyPair: ByteArray): ByteArray {
    return KeyPair.getIdentityPublicKey(keyPair)
}

public fun getSessionPublicKey(keyPair: ByteArray): ByteArray {
    return KeyPair.getSessionPublicKey(keyPair)
}

public fun getPublicKeys(
    identityKeyPair: ByteArray,
    sessionKeyPair: ByteArray,
): Pair<ByteArray, ByteArray> {
    return KeyPair.getPublicKeys(identityKeyPair, sessionKeyPair)
}
