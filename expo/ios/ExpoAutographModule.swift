import Autograph
import ExpoModulesCore
import Foundation

extension Data {
    func toBytes() -> [UInt8] {
        [UInt8](self)
    }
}

public class ExpoAutographModule: Module {
    public func definition() -> ModuleDefinition {
        Name("ExpoAutograph")

        Events("onReady")

        OnStartObserving {
            do {
                try Autograph.ready()
                sendEvent("onReady")
            } catch {}
        }

        Function("authenticate") {
            (ourIdentityKeyPair: Data, theirIdentityKey: Data) -> [String: Any?] in
            do {
                let safetyNumber = try Autograph.authenticate(
                    ourIdentityKeyPair.toBytes(),
                    [1, 2, 3],
                    theirIdentityKey.toBytes(),
                    [4, 5, 6]
                )
                return [
                    "success": true,
                    "safetyNumber": Data(safetyNumber),
                ]
            } catch {
                return [
                    "success": false,
                    "safetyNumber": Data(),
                ]
            }
        }

        Function("certify") {
            (ourIdentityKeyPair: Data, theirIdentityKey: Data, data: Data) -> [String: Any?] in
            do {
                let signature = try Autograph.certify(
                    ourIdentityKeyPair.toBytes(),
                    theirIdentityKey.toBytes(),
                    data.toBytes()
                )
                return ["success": true, "signature": Data(signature)]
            } catch {
                return [
                    "success": false,
                    "signature": Data(),
                ]
            }
        }

        Function("verify") {
            (ownerIdentityKey: Data, certifierIdentityKey: Data, signature: Data, data: Data) in
            Autograph.verify(
                ownerIdentityKey.toBytes(),
                certifierIdentityKey.toBytes(),
                signature.toBytes(),
                data.toBytes()
            )
        }

        Function("keyExchange") {
            (
                isInitiator: Bool,
                ourIdentityKeyPair: Data,
                ourSessionKeyPair: Data,
                theirIdentityKey: Data,
                theirSessionKey: Data
            ) -> [String: Any?] in
            do {
                let (
                    transcript,
                    ourSignature,
                    sendingKey,
                    receivingKey
                ) = try Autograph.keyExchange(
                    isInitiator,
                    ourIdentityKeyPair.toBytes(),
                    ourSessionKeyPair.toBytes(),
                    theirIdentityKey.toBytes(),
                    theirSessionKey.toBytes()
                )
                return [
                    "success": true,
                    "transcript": Data(transcript),
                    "ourSignature": Data(ourSignature),
                    "sendingKey": Data(sendingKey),
                    "receivingKey": Data(receivingKey),
                ]
            } catch {
                return [
                    "success": false,
                    "transcript": Data(),
                    "ourSignature": Data(),
                    "sendingKey": Data(),
                    "receivingKey": Data(),
                ]
            }
        }

        Function("verifyKeyExchange") {
            (
                transcript: Data,
                ourIdentityKeyPair: Data,
                theirIdentityKey: Data,
                theirSignature: Data
            ) -> Bool in
            do {
                try Autograph.verifyKeyExchange(
                    transcript.toBytes(),
                    ourIdentityKeyPair.toBytes(),
                    theirIdentityKey.toBytes(),
                    theirSignature.toBytes()
                )
                return true
            } catch {
                return false
            }
        }

        Function("generateIdentityKeyPair") { () -> [String: Any?] in
            do {
                let keyPair = try Autograph.generateIdentityKeyPair()
                return [
                    "success": true,
                    "keyPair": Data(keyPair),
                ]
            } catch {
                return [
                    "success": false,
                    "keyPair": Data(),
                ]
            }
        }

        Function("generateSessionKeyPair") { () -> [String: Any?] in
            do {
                let keyPair = try Autograph.generateSessionKeyPair()
                return [
                    "success": true,
                    "keyPair": Data(keyPair),
                ]
            } catch {
                return [
                    "success": false,
                    "keyPair": Data(),
                ]
            }
        }

        Function("getIdentityPublicKey") { (keyPair: Data) -> Data in
            let publicKey = Autograph.getIdentityPublicKey(keyPair.toBytes())
            return Data(publicKey)
        }

        Function("getSessionPublicKey") { (keyPair: Data) -> Data in
            let publicKey = Autograph.getSessionPublicKey(keyPair.toBytes())
            return Data(publicKey)
        }

        Function("getPublicKeys") {
            (identityKeyPair: Data, sessionKeyPair: Data) -> [String: Data] in
            let identityKey =
                Autograph
                .getIdentityPublicKey(identityKeyPair.toBytes())
            let sessionKey =
                Autograph
                .getSessionPublicKey(sessionKeyPair.toBytes())
            return [
                "identityKey": Data(identityKey),
                "sessionKey": Data(sessionKey),
            ]
        }

        Function("createNonce") { () -> Data in
            let nonce = Autograph.createNonce()
            return Data(nonce)
        }

        Function("createSkippedIndexes") { (count: UInt16) -> Data in
            let indexes = Autograph.createSkippedIndexes(count)
            return Data(indexes)
        }

        Function("generateSecretKey") { () -> [String: Any?] in
            do {
                let key = try Autograph.generateSecretKey()
                return [
                    "success": true,
                    "key": Data(key),
                ]
            } catch {
                return [
                    "success": false,
                    "key": Data(),
                ]
            }
        }

        Function("encrypt") { (key: Data, nonce: Data, plaintext: Data) -> [String: Any?] in
            do {
                var n = nonce.toBytes()
                let (index, ciphertext) = try Autograph.encrypt(
                    key.toBytes(),
                    &n,
                    plaintext.toBytes()
                )
                return [
                    "success": true,
                    "nonce": Data(n),
                    "index": index,
                    "ciphertext": Data(ciphertext),
                ]
            } catch {
                return [
                    "success": false,
                    "nonce": Data(),
                    "index": 0,
                    "ciphertext": Data(),
                ]
            }
        }

        Function("decrypt") {
            (key: Data, nonce: Data, skippedIndexes: Data, ciphertext: Data) -> [String: Any?] in
            do {
                var n = nonce.toBytes()
                var indexes = skippedIndexes.toBytes()
                let (index, plaintext) = try Autograph.decrypt(
                    key.toBytes(),
                    &n,
                    &indexes,
                    ciphertext.toBytes()
                )
                return [
                    "success": true,
                    "nonce": Data(n),
                    "skippedIndexes": Data(indexes),
                    "index": index,
                    "plaintext": Data(plaintext),
                ]
            } catch {
                return [
                    "success": false,
                    "nonce": Data(),
                    "skippedIndexes": Data(),
                    "index": 0,
                    "plaintext": Data(),
                ]
            }
        }
    }
}
