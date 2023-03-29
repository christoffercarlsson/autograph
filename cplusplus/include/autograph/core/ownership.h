#pragma once

int autograph_core_ownership_certify(unsigned char *signature,
                                     const unsigned char *our_private_key,
                                     const unsigned char *their_public_key,
                                     const unsigned char *data,
                                     unsigned long long data_size);

int autograph_core_ownership_verify(const unsigned char *their_identity_key,
                                    const unsigned char *their_secret_key,
                                    const unsigned char *certificates,
                                    const unsigned long long certificate_count,
                                    const unsigned char *message,
                                    const unsigned long long message_size);
