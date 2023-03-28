#pragma once

bool verify_ownership(const unsigned char *their_identity_key,
                      const unsigned char *their_secret_key,
                      const unsigned char *certificates,
                      const unsigned long long certificate_count,
                      const unsigned char *message,
                      const unsigned long long message_size);
