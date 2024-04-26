package sh.autograph

const val DEFAULT_SKIPPED_INDEXES_COUNT = 100
private fun createSkippedIndexes(count: Int?): IntArray {
    val size = count ?: DEFAULT_SKIPPED_INDEXES_COUNT
    return IntArray(size.toUShort().toInt()) { 0 }
}

class Channel {
    private var ourIdentityKeyPair: ByteArray = Helper.createKeyPair()
    private var ourSessionKeyPair: ByteArray = Helper.createKeyPair()
    private var theirIdentityKey: ByteArray = Helper.createPublicKey()
    private var theirSessionKey: ByteArray = Helper.createPublicKey()
    private var transcript: ByteArray = Helper.createTranscript()
    private var sendingKey: ByteArray = Helper.createSecretKey()
    private var receivingKey: ByteArray = Helper.createSecretKey()
    private var sendingNonce: ByteArray = Helper.createNonce()
    private var receivingNonce: ByteArray = Helper.createNonce()
    private var skippedIndexes: IntArray = IntArray(0)
    private var established: Boolean = false

    constructor(skippedIndexesCount: Int?) {
        skippedIndexes = createSkippedIndexes(skippedIndexesCount)
    }

    companion object {
        init {
            System.loadLibrary("autograph")
        }

        private external fun autographUseKeyPairs(
            identityKey: ByteArray,
            sessionKey: ByteArray,
            identityKeyPair: ByteArray,
            sessionKeyPair: ByteArray,
            ourIdentityKeyPair: ByteArray,
            ourSessionKeyPair: ByteArray,
        ): Boolean

        private external fun autographUsePublicKeys(
            identityKey: ByteArray,
            sessionKey: ByteArray,
            theirIdentityKey: ByteArray,
            theirSessionKey: ByteArray,
        )
    }

    fun isEstablished(): Boolean = established

    fun useKeyPairs(
        ourIdentityKeyPair: ByteArray,
        ourSessionKeyPair: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        established = false
        val identityKey = Helper.createPublicKey()
        val sessionKey = Helper.createPublicKey()
        val ready =
            Channel.autographUseKeyPairs(
                identityKey,
                sessionKey,
                this.ourIdentityKeyPair,
                this.ourSessionKeyPair,
                ourIdentityKeyPair,
                ourSessionKeyPair,
            )
        if (!ready) {
            throw RuntimeException("Initialization failed")
        }
        return Pair(identityKey, sessionKey)
    }

    fun usePublicKeys(
        theirIdentityKey: ByteArray,
        theirSessionKey: ByteArray,
    ) {
        established = false
        autographUsePublicKeys(this.theirIdentityKey, this.theirSessionKey, theirIdentityKey, theirSessionKey)
    }

    fun authenticate(): ByteArray {
        return Auth.authenticate(ourIdentityKeyPair, theirIdentityKey)
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
        established = false
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
        established = true
        Helper.zeroize(sendingNonce)
        Helper.zeroize(receivingNonce)
        skippedIndexes.fill(0)
    }

    fun encrypt(plaintext: ByteArray): Pair<Int, ByteArray> {
        if (established) {
            return Message.encrypt(sendingKey, sendingNonce, plaintext)
        } else {
            throw RuntimeException("Encryption failed")
        }
    }

    fun decrypt(ciphertext: ByteArray): Pair<Int, ByteArray> {
        if (established) {
            return Message.decrypt(receivingKey, receivingNonce, skippedIndexes, ciphertext)
        } else {
            throw RuntimeException("Decryption failed")
        }
    }

    fun close() {
        established = false
        Helper.zeroize(ourIdentityKeyPair)
        Helper.zeroize(ourSessionKeyPair)
        Helper.zeroize(sendingKey)
        Helper.zeroize(receivingKey)
        Helper.zeroize(sendingNonce)
        Helper.zeroize(receivingNonce)
        skippedIndexes.fill(0)
    }
}
