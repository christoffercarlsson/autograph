#pragma once

int autograph_core_session(const unsigned char *transcript,
                           const unsigned char *their_identity_key,
                           const unsigned char *their_secret_key,
                           const unsigned char *ciphertext);
