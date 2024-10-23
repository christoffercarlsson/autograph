package expo.modules.autograph

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import sh.autograph.authenticate
import sh.autograph.certify
import sh.autograph.createNonce
import sh.autograph.createSkippedIndexes
import sh.autograph.decrypt
import sh.autograph.encrypt
import sh.autograph.generateIdentityKeyPair
import sh.autograph.generateSecretKey
import sh.autograph.generateSessionKeyPair
import sh.autograph.getIdentityPublicKey
import sh.autograph.getSessionPublicKey
import sh.autograph.keyExchange
import sh.autograph.ready
import sh.autograph.verify
import sh.autograph.verifyKeyExchange

class ExpoAutographModule : Module() {
    override fun definition() =
        ModuleDefinition {
            Name("ExpoAutograph")

            Events("onReady")

            OnStartObserving {
                try {
                    ready()
                    sendEvent("onReady")
                } catch (e: Exception) {
                }
            }

            Function("authenticate") { ourIdentityKeyPair: ByteArray, theirIdentityKey: ByteArray ->
                try {
                    val safetyNumber =
                        authenticate(
                            ourIdentityKeyPair,
                            byteArrayOf(1, 2, 3),
                            theirIdentityKey,
                            byteArrayOf(4, 5, 6),
                        )
                    mapOf(
                        "success" to true,
                        "safetyNumber" to safetyNumber,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "safetyNumber" to ByteArray(0),
                    )
                }
            }

            Function("certify") { ourIdentityKeyPair: ByteArray, theirIdentityKey: ByteArray, data: ByteArray ->
                try {
                    val signature =
                        certify(
                            ourIdentityKeyPair,
                            theirIdentityKey,
                            data,
                        )
                    mapOf(
                        "success" to true,
                        "signature" to signature,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "signature" to ByteArray(0),
                    )
                }
            }

            Function("verify") { ownerIdentityKey: ByteArray, certifierIdentityKey: ByteArray, signature: ByteArray, data: ByteArray ->
                verify(
                    ownerIdentityKey,
                    certifierIdentityKey,
                    signature,
                    data,
                )
            }

            Function(
                "keyExchange",
            ) {
                    isInitiator: Boolean,
                    ourIdentityKeyPair: ByteArray,
                    ourSessionKeyPair: ByteArray,
                    theirIdentityKey: ByteArray,
                    theirSessionKey: ByteArray,
                ->
                try {
                    val (transcript, ourSignature, sendingKey, receivingKey) =
                        keyExchange(
                            isInitiator,
                            ourIdentityKeyPair,
                            ourSessionKeyPair,
                            theirIdentityKey,
                            theirSessionKey,
                        )
                    mapOf(
                        "success" to true,
                        "transcript" to transcript,
                        "ourSignature" to ourSignature,
                        "sendingKey" to sendingKey,
                        "receivingKey" to receivingKey,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "transcript" to ByteArray(0),
                        "ourSignature" to ByteArray(0),
                        "sendingKey" to ByteArray(0),
                        "receivingKey" to ByteArray(0),
                    )
                }
            }

            Function(
                "verifyKeyExchange",
            ) { transcript: ByteArray, ourIdentityKeyPair: ByteArray, theirIdentityKey: ByteArray, theirSignature: ByteArray ->
                try {
                    verifyKeyExchange(
                        transcript,
                        ourIdentityKeyPair,
                        theirIdentityKey,
                        theirSignature,
                    )
                    true
                } catch (e: Exception) {
                    false
                }
            }

            Function("generateIdentityKeyPair") {
                try {
                    val keyPair = generateIdentityKeyPair()
                    mapOf(
                        "success" to true,
                        "keyPair" to keyPair,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "keyPair" to ByteArray(0),
                    )
                }
            }

            Function("generateSessionKeyPair") {
                try {
                    val keyPair = generateSessionKeyPair()
                    mapOf(
                        "success" to true,
                        "keyPair" to keyPair,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "keyPair" to ByteArray(0),
                    )
                }
            }

            Function("getIdentityPublicKey") { keyPair: ByteArray ->
                getIdentityPublicKey(keyPair)
            }

            Function("getSessionPublicKey") { keyPair: ByteArray ->
                getSessionPublicKey(keyPair)
            }

            Function("getPublicKeys") { identityKeyPair: ByteArray, sessionKeyPair: ByteArray ->
                val identityKey = getIdentityPublicKey(identityKeyPair)
                val sessionKey = getSessionPublicKey(sessionKeyPair)
                mapOf(
                    "identityKey" to identityKey,
                    "sessionKey" to sessionKey,
                )
            }

            Function("createNonce") {
                createNonce()
            }

            Function("createSkippedIndexes") { count: Int ->
                createSkippedIndexes(count)
            }

            Function("generateSecretKey") {
                try {
                    val key = generateSecretKey()
                    mapOf(
                        "success" to true,
                        "key" to key,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "key" to ByteArray(0),
                    )
                }
            }

            Function("encrypt") { key: ByteArray, nonce: ByteArray, plaintext: ByteArray ->
                try {
                    val (index, ciphertext) =
                        encrypt(
                            key,
                            nonce,
                            plaintext,
                        )
                    mapOf(
                        "success" to true,
                        "nonce" to nonce.copyOf(),
                        "index" to index,
                        "ciphertext" to ciphertext,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "nonce" to ByteArray(0),
                        "index" to 0,
                        "ciphertext" to ByteArray(0),
                    )
                }
            }

            Function("decrypt") { key: ByteArray, nonce: ByteArray, skippedIndexes: ByteArray, ciphertext: ByteArray ->
                try {
                    val (index, plaintext) =
                        decrypt(
                            key,
                            nonce,
                            skippedIndexes,
                            ciphertext,
                        )
                    mapOf(
                        "success" to true,
                        "nonce" to nonce.copyOf(),
                        "skippedIndexes" to skippedIndexes.copyOf(),
                        "index" to index,
                        "plaintext" to plaintext,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "nonce" to ByteArray(0),
                        "skippedIndexes" to ByteArray(0),
                        "index" to 0,
                        "plaintext" to ByteArray(0),
                    )
                }
            }
        }
}
