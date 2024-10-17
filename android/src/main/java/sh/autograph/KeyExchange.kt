package sh.autograph

internal class KeyExchange {
    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographTranscriptSize(): Int

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

        fun createTranscript(): ByteArray = ByteArray(autographTranscriptSize())

        fun keyExchange(
            isInitiator: Boolean,
            ourIdentityKeyPair: ByteArray,
            ourSessionKeyPair: ByteArray,
            theirIdentityKey: ByteArray,
            theirSessionKey: ByteArray,
        ): Array<ByteArray> {
            var transcript = createTranscript()
            var ourSignature = Cert.createSignature()
            var sendingKey = Message.createSecretKey()
            var receivingKey = Message.createSecretKey()
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
                throw RuntimeException("Key exchange failed")
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
                throw RuntimeException("Key exchange failed")
            }
        }
    }
}

public fun keyExchange(
    isInitiator: Boolean,
    ourIdentityKeyPair: ByteArray,
    ourSessionKeyPair: ByteArray,
    theirIdentityKey: ByteArray,
    theirSessionKey: ByteArray,
): Array<ByteArray> {
    return KeyExchange.keyExchange(isInitiator, ourIdentityKeyPair, ourSessionKeyPair, theirIdentityKey, theirSessionKey)
}

public fun verifyKeyExchange(
    transcript: ByteArray,
    ourIdentityKeyPair: ByteArray,
    theirIdentityKey: ByteArray,
    theirSignature: ByteArray,
) {
    return KeyExchange.verifyKeyExchange(transcript, ourIdentityKeyPair, theirIdentityKey, theirSignature)
}
