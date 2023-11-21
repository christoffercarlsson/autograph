import Clibautograph
import Foundation

let HANDSHAKE_SIZE = autograph_handshake_size()
let INDEX_SIZE = autograph_index_size()
let PRIVATE_KEY_SIZE = autograph_private_key_size()
let PUBLIC_KEY_SIZE = autograph_public_key_size()
let SAFETY_NUMBER_SIZE = autograph_safety_number_size()
let SECRET_KEY_SIZE = autograph_safety_number_size()
let SIGNATURE_SIZE = autograph_signature_size()
let SIZE_SIZE = autograph_size_size()
let SKIPPED_KEYS_SIZE = autograph_skipped_keys_size()
let TRANSCRIPT_SIZE = autograph_transcript_size()

func createBytes(_ size: Int) -> [UInt8] {
  [UInt8](repeating: 0, count: size)
}

func createBytes(_ size: UInt32) -> [UInt8] {
  createBytes(Int(size))
}

func createCiphertextBytes(_ size: Int) -> [UInt8] {
  let ciphertextSize = autograph_ciphertext_size(UInt32(size))
  return createBytes(ciphertextSize)
}

func createHandshakeBytes() -> [UInt8] {
  createBytes(HANDSHAKE_SIZE)
}

func createIndexBytes() -> [UInt8] {
  createBytes(INDEX_SIZE)
}

func createPlaintextBytes(_ size: Int) -> [UInt8] {
  let plaintextSize = autograph_plaintext_size(UInt32(size))
  return createBytes(plaintextSize)
}

func createPrivateKeyBytes() -> [UInt8] {
  createBytes(PRIVATE_KEY_SIZE)
}

func createPublicKeyBytes() -> [UInt8] {
  createBytes(PUBLIC_KEY_SIZE)
}

func createSafetyNumberBytes() -> [UInt8] {
  createBytes(SAFETY_NUMBER_SIZE)
}

func createSecretKeyBytes() -> [UInt8] {
  createBytes(SECRET_KEY_SIZE)
}

func createSignatureBytes() -> [UInt8] {
  createBytes(SIGNATURE_SIZE)
}

func createSizeBytes() -> [UInt8] {
  createBytes(SIZE_SIZE)
}

func createSkippedKeysBytes() -> [UInt8] {
  createBytes(SKIPPED_KEYS_SIZE)
}

func createSubjectBytes(_ size: Int) -> [UInt8] {
  let subjectSize = autograph_subject_size(UInt32(size))
  return createBytes(subjectSize)
}

func createTranscriptBytes() -> [UInt8] {
  createBytes(TRANSCRIPT_SIZE)
}
