#pragma once

bool derive_secret_keys(unsigned char *our_secret_key,
                        unsigned char *their_secret_key, bool is_initiator,
                        const unsigned char *our_private_key,
                        const unsigned char *their_public_key);
