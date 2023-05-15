#pragma once

namespace autograph {

constexpr unsigned int CHACHA_NONCE_SIZE = 12;
constexpr unsigned int CHACHA_TAG_SIZE = 16;
constexpr unsigned char CONTEXT_INITIATOR = 0x00;
constexpr unsigned char CONTEXT_RESPONDER = 0x01;
constexpr unsigned int DH_OUTPUT_SIZE = 32;
constexpr unsigned int DIGEST_SIZE = 64;
constexpr unsigned int MESSAGE_EXTRA_SIZE = 4 + CHACHA_TAG_SIZE;
constexpr unsigned int PRIVATE_KEY_SIZE = 32;
constexpr unsigned int PUBLIC_KEY_SIZE = 32;
constexpr unsigned int SECRET_KEY_SIZE = 32;
constexpr unsigned int SAFETY_NUMBER_DIVISOR = 100000;
constexpr unsigned int SAFETY_NUMBER_FINGERPRINT_SIZE = 30;
constexpr unsigned int SAFETY_NUMBER_CHUNK_SIZE =
    SAFETY_NUMBER_FINGERPRINT_SIZE / 6;
constexpr unsigned int SAFETY_NUMBER_ITERATIONS = 5200;
constexpr unsigned int SAFETY_NUMBER_SIZE = SAFETY_NUMBER_FINGERPRINT_SIZE * 2;
constexpr unsigned int SIGNATURE_SIZE = 64;
constexpr unsigned int HANDSHAKE_SIZE = SIGNATURE_SIZE + CHACHA_TAG_SIZE;
constexpr unsigned int TRANSCRIPT_SIZE = PUBLIC_KEY_SIZE * 4;

}  // namespace autograph
