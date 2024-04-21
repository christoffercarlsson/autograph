import Clibautograph
import Foundation

public typealias Bytes = [UInt8]

func createBytes(_ size: Int) -> Bytes {
    Bytes(repeating: 0, count: size)
}

func createKeyPair() -> Bytes {
    createBytes(autograph_key_pair_size())
}

func createNonce() -> Bytes {
    createBytes(autograph_nonce_size())
}

func createPublicKey() -> Bytes {
    createBytes(autograph_public_key_size())
}

func createSecretKey() -> Bytes {
    createBytes(autograph_secret_key_size())
}

func createSignature() -> Bytes {
    createBytes(autograph_signature_size())
}

func createTranscript() -> Bytes {
    createBytes(autograph_transcript_size())
}

public func zeroize(data: inout Bytes) {
    autograph_zeroize(&data, data.count)
}

public func isZero(data: Bytes) -> Bool {
    autograph_is_zero(data, data.count)
}
