#pragma once

bool sign_message(unsigned char *signature, const unsigned char *private_key,
                  const unsigned char *message,
                  unsigned long long message_size);
