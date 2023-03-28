#pragma once

bool certify_ownership(unsigned char *signature,
                       const unsigned char *our_private_key,
                       const unsigned char *their_public_key,
                       const unsigned char *data, unsigned long long data_size);
