package expo.modules.autograph

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import sh.autograph.authenticate
import sh.autograph.certify
import sh.autograph.decrypt
import sh.autograph.encrypt
import sh.autograph.generateIdentityKeyPair
import sh.autograph.generateSecretKey
import sh.autograph.generateSessionKeyPair
import sh.autograph.getIdentityPublicKey
import sh.autograph.getPublicKeys
import sh.autograph.getSessionPublicKey
import sh.autograph.keyExchange
import sh.autograph.ready
import sh.autograph.verify
import sh.autograph.verifyKeyExchange

fun ByteArray.toIndexes(): IntArray {
    if (this.size % 4 > 0) {
        return IntArray()
    }
    val indexes = IntArray(this.size / 4)
    for (i in indexes.indices) {
        val offset = i * 4
        val value =
            (this[offset].toInt() and 0xFF shl 24) or
                (this[offset + 1].toInt() and 0xFF shl 16) or
                (this[offset + 2].toInt() and 0xFF shl 8) or
                (this[offset + 3].toInt() and 0xFF)
        indexes[i] = value
    }
    return indexes
}

fun IntArray.toBytes(): ByteArray {
    val bytes = ByteArray(this.size * 4)
    for (i in this.indices) {
        val offset = i * 4
        val value = this[i]
        bytes[offset] = ((value shr 24) and 0xFF).toByte()
        bytes[offset + 1] = ((value shr 16) and 0xFF).toByte()
        bytes[offset + 2] = ((value shr 8) and 0xFF).toByte()
        bytes[offset + 3] = (value and 0xFF).toByte()
    }
    return bytes
}

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
                            theirIdentityKey,
                        )
                    mapOf(
                        "success" to true,
                        "safetyNumber" to safetyNumber,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "safetyNumber" to ByteArray(),
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
                        "signature" to ByteArray(),
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
                        "transcript" to ByteArray(),
                        "ourSignature" to ByteArray(),
                        "sendingKey" to ByteArray(),
                        "receivingKey" to ByteArray(),
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
                        "keyPair" to ByteArray(),
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
                        "keyPair" to ByteArray(),
                    )
                }
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
                        "key" to ByteArray(),
                    )
                }
            }

            Function("encrypt") { key: ByteArray, nonce: ByteArray, plaintext: ByteArray ->
                try {
                    var n = nonce
                    val (index, ciphertext) =
                        encrypt(
                            key,
                            n,
                            plaintext,
                        )
                    mapOf(
                        "success" to true,
                        "nonce" to ByteArray(),
                        "index" to index,
                        "ciphertext" to ciphertext,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "nonce" to ByteArray(),
                        "index" to 0,
                        "ciphertext" to ByteArray(),
                    )
                }
            }

            Function("decrypt") { key: ByteArray, nonce: ByteArray, skippedIndexes: ByteArray, ciphertext: ByteArray ->
                try {
                    var n = nonce
                    val indexes = IntArray(1)
                    val (index, plaintext) =
                        decrypt(
                            key,
                            n,
                            indexes,
                            ciphertext,
                        )
                    mapOf(
                        "success" to true,
                        "nonce" to ByteArray(),
                        "skippedIndexes" to ByteArray(),
                        "index" to index,
                        "plaintext" to plaintext,
                    )
                } catch (e: Exception) {
                    mapOf(
                        "success" to false,
                        "nonce" to ByteArray(),
                        "skippedIndexes" to ByteArray(),
                        "index" to 0,
                        "plaintext" to ByteArray(),
                    )
                }
            }
        }
}
