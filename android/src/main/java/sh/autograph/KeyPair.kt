package sh.autograph

class KeyPair {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographIdentityKeyPair(keyPair: ByteArray): Boolean

        private external fun autographSessionKeyPair(keyPair: ByteArray): Boolean

        fun generateIdentityKeyPair(): ByteArray {
            val keyPair = Helper.createKeyPair()
            val success = autographIdentityKeyPair(keyPair)
            if (!success) {
                throw RuntimeException("Key generation failed")
            }
            return keyPair
        }

        fun generateSessionKeyPair(): ByteArray {
            val keyPair = Helper.createKeyPair()
            val success = autographSessionKeyPair(keyPair)
            if (!success) {
                throw RuntimeException("Key generation failed")
            }
            return keyPair
        }
    }
}
