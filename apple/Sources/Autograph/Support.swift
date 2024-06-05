import Clibautograph
import Foundation

func createBytes(_ size: Int) -> [UInt8] {
    [UInt8](repeating: 0, count: size)
}

func createKeyPair() -> [UInt8] {
    createBytes(autograph_key_pair_size())
}

func createNonce() -> [UInt8] {
    createBytes(autograph_nonce_size())
}

func createPublicKey() -> [UInt8] {
    createBytes(autograph_public_key_size())
}

func createSafetyNumber() -> [UInt8] {
    createBytes(autograph_safety_number_size())
}

func createSecretKey() -> [UInt8] {
    createBytes(autograph_secret_key_size())
}

func createSignature() -> [UInt8] {
    createBytes(autograph_signature_size())
}

func createSkippedIndexes() -> [UInt32] {
    [UInt32](repeating: 0, count: Int(autograph_skipped_indexes_count()))
}

func createTranscript() -> [UInt8] {
    createBytes(autograph_transcript_size())
}

public func ready() throws {
    if !autograph_ready() {
        throw AutographError.initialization
    }
}
