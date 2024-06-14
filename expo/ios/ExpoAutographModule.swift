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

        Function("authenticate") { (ourIdentityKeyPair: Data, theirIdentityKey: Data) -> [String: Any?] in
            do {
                let safetyNumber = try Autograph.authenticate(
                    ourIdentityKeyPair.toBytes(),
                    theirIdentityKey.toBytes()
                )
                return [
                    "success": true,
                    "safetyNumber": Data(safetyNumber),
                ]
            } catch {
                return [
                    "success": false,
                    "safetyNumber": Data(repeating: 0, count: 64),
                ]
            }
        }

        Function("certify") { (ourIdentityKeyPair: Data, theirIdentityKey: Data, data: Data) -> [String: Any?] in
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
                    "signature": Data(repeating: 0, count: 64),
                ]
            }
        }

        Function("verify") { (ownerIdentityKey: Data, certifierIdentityKey: Data, signature: Data, data: Data) in
            Autograph.verify(
                ownerIdentityKey.toBytes(),
                certifierIdentityKey.toBytes(),
                signature.toBytes(),
                data.toBytes()
            )
        }

        Function("keyExchange") { (isInitiator: Bool, ourIdentityKeyPair: Data, ourSessionKeyPair: Data, theirIdentityKey: Data, theirSessionKey: Data) -> [String: Any?] in
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
                    "transcript": Data(repeating: 0, count: 64),
                    "ourSignature": Data(repeating: 0, count: 64),
                    "sendingKey": Data(repeating: 0, count: 32),
                    "receivingKey": Data(repeating: 0, count: 32),
                ]
            }
        }

        Function("verifyKeyExchange") { (transcript: Data, ourIdentityKeyPair: Data, theirIdentityKey: Data, theirSignature: Data) -> Bool in
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
                    "keyPair": Data(repeating: 0, count: 64),
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
                    "keyPair": Data(repeating: 0, count: 64),
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

        Function("getPublicKeys") { (identityKeyPair: Data, sessionKeyPair: Data) -> [String: Any?] in
            let (identityKey, sessionKey) = Autograph.getPublicKeys(
                identityKeyPair.toBytes(),
                sessionKeyPair.toBytes()
            )
            return [
                "identityKey": Data(identityKey),
                "sessionKey": Data(sessionKey),
            ]
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
                    "key": Data(repeating: 0, count: 32),
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
                    "index": index,
                    "ciphertext": Data(ciphertext),
                ]
            } catch {
                return [
                    "success": false,
                    "index": 0,
                    "ciphertext": Data(repeating: 0,
                                       count: plaintext.count + 16),
                ]
            }
        }

        Function("decrypt") { (key: Data, nonce: Data, _: Data, ciphertext: Data) -> [String: Any?] in
            do {
                var n = nonce.toBytes()
                var indexes: [UInt32] = [0, 0, 0]
                let (index, plaintext) = try Autograph.decrypt(
                    key.toBytes(),
                    &n,
                    &indexes,
                    ciphertext.toBytes()
                )
                return [
                    "success": true,
                    "index": index,
                    "plaintext": Data(plaintext),
                ]
            } catch {
                return [
                    "success": false,
                    "index": 0,
                    "plaintext": Data(repeating: 0,
                                      count: ciphertext.count - 16),
                ]
            }
        }
    }
}
