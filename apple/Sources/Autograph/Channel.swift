import Clibautograph
import Foundation

private func createHello() -> Bytes {
    createBytes(autograph_hello_size())
}

private func createIndex() -> Bytes {
    createBytes(autograph_index_size())
}

private func createSafetyNumber() -> Bytes {
    createBytes(autograph_safety_number_size())
}

private func createSecretKey() -> Bytes {
    createBytes(autograph_secret_key_size())
}

private func createSignature() -> Bytes {
    createBytes(autograph_signature_size())
}

private func createSize() -> Bytes {
    createBytes(autograph_size_size())
}

private func createStateBytes() -> Bytes {
    createBytes(autograph_state_size())
}

private func createCiphertext(_ plaintext: Bytes) -> Bytes {
    let size = autograph_ciphertext_size(plaintext.count)
    return createBytes(size)
}

private func createPlaintext(_ ciphertext: Bytes) -> Bytes {
    let size = autograph_plaintext_size(ciphertext.count)
    return createBytes(size)
}

private func createSessionCiphertext(_ state: Bytes) -> Bytes {
    let size = autograph_ciphertext_size(autograph_session_size(state))
    return createBytes(size)
}

private func readIndex(_ bytes: Bytes) -> UInt32 {
    autograph_read_index(bytes)
}

private func readSize(_ bytes: Bytes) -> Int {
    Int(autograph_read_size(bytes))
}

private func resizePlaintext(_ plaintext: Bytes, _ size: Bytes) -> Bytes {
    Array(plaintext[0 ..< readSize(size)])
}

public class Channel {
    var state: Bytes

    public init() {
        state = createStateBytes()
    }

    public func useKeyPairs(
        identityKeyPair: Bytes,
        ephemeralKeyPair: Bytes
    ) throws -> Bytes {
        var publicKeys = createHello()
        let success = autograph_use_key_pairs(
            &publicKeys,
            &state,
            identityKeyPair,
            ephemeralKeyPair
        )
        if !success {
            throw AutographError.initialization
        }
        return publicKeys
    }

    public func usePublicKeys(publicKeys: Bytes) {
        autograph_use_public_keys(&state, publicKeys)
    }

    public func authenticate() throws -> Bytes {
        var safetyNumber = createSafetyNumber()
        let success = autograph_authenticate(&safetyNumber, &state)
        if !success {
            throw AutographError.authentication
        }
        return safetyNumber
    }

    public func keyExchange(isInitiator: Bool) throws -> Bytes {
        var signature = createSignature()
        let success = autograph_key_exchange(
            &signature,
            &state,
            isInitiator
        )
        if !success {
            throw AutographError.keyExchange
        }
        return signature
    }

    public func verifyKeyExchange(signature: Bytes) throws {
        let success = autograph_verify_key_exchange(&state, signature)
        if !success {
            throw AutographError.keyExchange
        }
    }

    public func encrypt(plaintext: Bytes) throws -> (UInt32, Bytes) {
        var ciphertext = createCiphertext(plaintext)
        var index = createIndex()
        let success = autograph_encrypt_message(
            &ciphertext,
            &index,
            &state,
            plaintext,
            plaintext.count
        )
        if !success {
            throw AutographError.encryption
        }
        return (readIndex(index), ciphertext)
    }

    public func decrypt(message: Bytes) throws -> (UInt32, Bytes) {
        var plaintext = createPlaintext(message)
        var index = createIndex()
        var size = createSize()
        let success = autograph_decrypt_message(
            &plaintext,
            &size,
            &index,
            &state,
            message,
            message.count
        )
        if !success {
            throw AutographError.decryption
        }
        return (readIndex(index), resizePlaintext(plaintext, size))
    }

    public func certifyData(data: Bytes) throws -> Bytes {
        var signature = createSignature()
        let success = autograph_certify_data(
            &signature,
            &state,
            data,
            data.count
        )
        if !success {
            throw AutographError.certification
        }
        return signature
    }

    public func certifyIdentity() throws -> Bytes {
        var signature = createSignature()
        let success = autograph_certify_identity(
            &signature,
            &state
        )
        if !success {
            throw AutographError.certification
        }
        return signature
    }

    public func verifyData(
        data: Bytes,
        publicKey: Bytes,
        signature: Bytes
    ) -> Bool {
        autograph_verify_data(
            &state,
            data,
            data.count,
            publicKey,
            signature
        )
    }

    public func verifyIdentity(
        publicKey: Bytes,
        signature: Bytes
    ) -> Bool {
        autograph_verify_identity(
            &state,
            publicKey,
            signature
        )
    }

    public func close() throws -> (Bytes, Bytes) {
        var key = createSecretKey()
        var ciphertext = createSessionCiphertext(state)
        let success = autograph_close_session(&key, &ciphertext, &state)
        if !success {
            throw AutographError.session
        }
        return (key, ciphertext)
    }

    public func open(key: inout Bytes, ciphertext: Bytes) throws {
        let success = autograph_open_session(
            &state,
            &key,
            ciphertext,
            ciphertext.count
        )
        if !success {
            throw AutographError.session
        }
    }
}
