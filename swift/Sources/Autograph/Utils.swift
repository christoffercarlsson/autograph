import Clibautograph
import Foundation

internal let HANDSHAKE_SIZE = Int(autograph_handshake_size())
internal let MESSAGE_EXTRA_SIZE = Int(autograph_message_extra_size())
internal let PRIVATE_KEY_SIZE = Int(autograph_private_key_size())
internal let PUBLIC_KEY_SIZE = Int(autograph_public_key_size())
internal let SAFETY_NUMBER_SIZE = Int(autograph_safety_number_size())
internal let SECRET_KEY_SIZE = Int(autograph_secret_key_size())
internal let SIGNATURE_SIZE = Int(autograph_signature_size())
internal let TRANSCRIPT_SIZE = Int(autograph_transcript_size())

private func createBytes(_ size: Int) -> Bytes {
  Bytes(repeating: 0, count: size > 0 ? size : 0)
}

internal func createHandshakeBytes() -> Bytes {
  createBytes(HANDSHAKE_SIZE)
}

internal func createMessageBytes(size: Int) -> Bytes {
  createBytes(size + MESSAGE_EXTRA_SIZE)
}

internal func createPlaintextBytes(size: Int) -> Bytes {
  createBytes(size - MESSAGE_EXTRA_SIZE)
}

internal func createPrivateKeyBytes() -> Bytes {
  createBytes(PRIVATE_KEY_SIZE)
}

internal func createPublicKeyBytes() -> Bytes {
  createBytes(PUBLIC_KEY_SIZE)
}

internal func createSafetyNumberBytes() -> Bytes {
  createBytes(SAFETY_NUMBER_SIZE)
}

internal func createSecretKeyBytes() -> Bytes {
  createBytes(SECRET_KEY_SIZE)
}

internal func createSignatureBytes() -> Bytes {
  createBytes(SIGNATURE_SIZE)
}

internal func createTranscriptBytes() -> Bytes {
  createBytes(TRANSCRIPT_SIZE)
}
