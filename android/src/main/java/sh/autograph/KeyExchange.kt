package sh.autograph

class KeyExchange {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographKeyExchange(
            transcript: ByteArray,
            ourSignature: ByteArray,
            sendingKey: ByteArray,
            receivingKey: ByteArray,
            isInitiator: Boolean,
            ourIdentityKeyPair: ByteArray,
            ourSessionKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
            theirSessionKey: ByteArray,
        ): Boolean

        private external fun autographVerifyKeyExchange(
            transcript: ByteArray,
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
            theirSignature: ByteArray,
        ): Boolean

        fun keyExchange(
            isInitiator: Boolean,
            ourIdentityKeyPair: ByteArray,
            ourSessionKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
            theirSessionKey: ByteArray,
        ): Array<ByteArray> {
            var transcript = Helper.createTranscript()
            var ourSignature = Helper.createSignature()
            var sendingKey = Helper.createSecretKey()
            var receivingKey = Helper.createSecretKey()
            val success =
                autographKeyExchange(
                    transcript,
                    ourSignature,
                    sendingKey,
                    receivingKey,
                    isInitiator,
                    ourIdentityKeyPair,
                    ourSessionKeyPair,
                    theirIdentityKey,
                    theirSessionKey,
                )
            if (!success) {
                throw RuntimeException("Key exhange failed")
            }
            return arrayOf(transcript, ourSignature, sendingKey, receivingKey)
        }

        fun verifyKeyExchange(
            transcript: ByteArray,
            ourIdentityKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
            theirSignature: ByteArray,
        ) {
            val verified = autographVerifyKeyExchange(transcript, ourIdentityKeyPair, theirIdentityKey, theirSignature)
            if (!verified) {
                throw RuntimeException("Key exhange failed")
            }
        }
    }
}
