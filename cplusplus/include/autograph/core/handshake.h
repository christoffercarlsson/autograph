#pragma once

constexpr unsigned char autograph_core_handshake_CONTEXT_INITIATOR = 0x00;
constexpr unsigned char autograph_core_handshake_CONTEXT_RESPONDER = 0x01;
constexpr unsigned int autograph_core_handshake_SIZE = 80;
constexpr unsigned int autograph_core_handshake_TRANSCRIPT_SIZE = 128;

int autograph_core_handshake(unsigned char *transcript,
                             unsigned char *ciphertext,
                             unsigned char *our_secret_key,
                             unsigned char *their_secret_key,
                             const unsigned int is_initiator,
                             const unsigned char *our_private_identity_key,
                             const unsigned char *our_public_identity_key,
                             const unsigned char *our_private_ephemeral_key,
                             const unsigned char *our_public_ephemeral_key,
                             const unsigned char *their_public_identity_key,
                             const unsigned char *their_public_ephemeral_key);
