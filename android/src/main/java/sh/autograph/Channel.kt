package sh.autograph

public class Channel {
    private var ourIdentityKeyPair: ByteArray = KeyPair.createIdentityKeyPair()
    private var ourSessionKeyPair: ByteArray = KeyPair.createSessionKeyPair()
    private var theirIdentityKey: ByteArray = KeyPair.createIdentityPublicKey()
    private var theirSessionKey: ByteArray = KeyPair.createSessionPublicKey()
    private var transcript: ByteArray = KeyExchange.createTranscript()
    private var sendingKey: ByteArray = Message.createSecretKey()
    private var receivingKey: ByteArray = Message.createSecretKey()
    private var sendingNonce: ByteArray = Message.createNonce()
    private var receivingNonce: ByteArray = Message.createNonce()
    private var skippedIndexes: ByteArray = Message.createSkippedIndexes(null)

    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographUseKeyPairs(
            identityKeyPair: ByteArray,
            sessionKeyPair: ByteArray,
            ourIdentityKeyPair: ByteArray,
            ourSessionKeyPair: ByteArray,
        )

        private external fun autographUsePublicKeys(
            identityKey: ByteArray,
            sessionKey: ByteArray,
            theirIdentityKey: ByteArray,
            theirSessionKey: ByteArray,
        )
    }

    fun useKeyPairs(
        ourIdentityKeyPair: ByteArray,
        ourSessionKeyPair: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        autographUseKeyPairs(
            this.ourIdentityKeyPair,
            this.ourSessionKeyPair,
            ourIdentityKeyPair,
            ourSessionKeyPair,
        )
        return KeyPair.getPublicKeys(ourIdentityKeyPair, ourSessionKeyPair)
    }

    fun usePublicKeys(
        theirIdentityKey: ByteArray,
        theirSessionKey: ByteArray,
    ) {
        autographUsePublicKeys(
            this.theirIdentityKey,
            this.theirSessionKey,
            theirIdentityKey,
            theirSessionKey,
        )
    }

    fun authenticate(
        ourId: ByteArray,
        theirId: ByteArray,
    ): ByteArray {
        return Auth.authenticate(ourIdentityKeyPair, ourId, theirIdentityKey, theirId)
    }

    fun certify(data: ByteArray?): ByteArray {
        return Cert.certify(ourIdentityKeyPair, theirIdentityKey, data)
    }

    fun verify(
        certifierIdentityKey: ByteArray,
        signature: ByteArray,
        data: ByteArray?,
    ): Boolean {
        return Cert.verify(theirIdentityKey, certifierIdentityKey, signature, data)
    }

    fun keyExchange(isInitiator: Boolean): ByteArray {
        val (transcript, ourSignature, sendingKey, receivingKey) =
            KeyExchange.keyExchange(
                isInitiator,
                ourIdentityKeyPair,
                ourSessionKeyPair,
                theirIdentityKey,
                theirSessionKey,
            )
        this.transcript = transcript
        this.sendingKey = sendingKey
        this.receivingKey = receivingKey
        return ourSignature
    }

    fun verifyKeyExchange(theirSignature: ByteArray) {
        KeyExchange.verifyKeyExchange(transcript, ourIdentityKeyPair, theirIdentityKey, theirSignature)
    }

    fun encrypt(plaintext: ByteArray): Pair<Int, ByteArray> {
        return Message.encrypt(sendingKey, sendingNonce, plaintext)
    }

    fun decrypt(ciphertext: ByteArray): Pair<Int, ByteArray> {
        return Message.decrypt(receivingKey, receivingNonce, skippedIndexes, ciphertext)
    }
}
