import Autograph
import ExpoModulesCore
import Foundation

extension Data {
    func toBytes() -> [UInt8] {
        [UInt8](self)
    }

    func toIndexes() -> [UInt32] {
        guard count % MemoryLayout<UInt32>.size == 0 else {
            return Array()
        }
        return withUnsafeBytes { rawPointer in
            let pointer = rawPointer.bindMemory(to: UInt32.self)
            return Array(pointer)
        }
    }
}

extension Array where Element == UInt32 {
    func toBytes() -> [UInt8] {
        var bytes = [UInt8]()
        for value in self {
            let chunk = [
                UInt8((value >> 24) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8(value & 0xFF),
            ]
            bytes.append(contentsOf: chunk)
        }
        return bytes
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
                    "safetyNumber": Data(),
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
                    "signature": Data(),
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

        Function("keyExchange") { (
            isInitiator: Bool,
            ourIdentityKeyPair: Data,
            ourSessionKeyPair: Data,
            theirIdentityKey: Data,
            theirSessionKey: Data) -> [String: Any?] in
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

        Function("verifyKeyExchange") { (
            transcript: Data,
            ourIdentityKeyPair: Data,
            theirIdentityKey: Data,
            theirSignature: Data) -> Bool in
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

        Function("decrypt") { (key: Data, nonce: Data, _: Data, ciphertext: Data) -> [String: Any?] in
            do {
                var n = nonce.toBytes()
                var indexes = []
                let (index, plaintext) = try Autograph.decrypt(
                    key.toBytes(),
                    &n,
                    &indexes,
                    ciphertext.toBytes()
                )
                return [
                    "success": true,
                    "nonce": Data(n),
                    "skippedIndexes": Data(),
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
