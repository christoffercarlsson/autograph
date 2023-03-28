#pragma once

bool handshake(unsigned char *transcript, unsigned char *ciphertext,
               unsigned char *our_secret_key, unsigned char *their_secret_key,
               bool is_initiator, const unsigned char *our_private_identity_key,
               const unsigned char *our_public_identity_key,
               const unsigned char *our_private_ephemeral_key,
               const unsigned char *our_public_ephemeral_key,
               const unsigned char *their_public_identity_key,
               const unsigned char *their_public_ephemeral_key);
