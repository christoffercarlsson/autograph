package sh.autograph

class Cert {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographCertify(
            signature: ByteArray,
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
            data: ByteArray,
        ): Boolean

        private external fun autographVerify(
            ownerIdentityKey: ByteArray,
            certifierIdentityKey: ByteArray,
            signature: ByteArray,
            data: ByteArray,
        ): Boolean

        fun certify(
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
            data: ByteArray?
        ): ByteArray {
            val signature = Helper.createSignature()
            val success = autographCertify(signature, ourIdentityKeyPair, theirIdentityKey,
                data ?: byteArrayOf()
            )
            if (!success) {
                throw RuntimeException("Certification failed")
            }
            return signature
        }

        fun verify(
            ownerIdentityKey: ByteArray,
            certifierIdentityKey: ByteArray,
            signature: ByteArray,
            data: ByteArray?
        ): Boolean {
            return autographVerify(ownerIdentityKey, certifierIdentityKey, signature,
                data ?: byteArrayOf()
            )
        }
    }
}
