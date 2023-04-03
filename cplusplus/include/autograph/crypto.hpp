#pragma once

namespace autograph {

bool decrypt(unsigned char *plaintext, const unsigned char *key,
             const unsigned int index, const unsigned char *ciphertext,
             const unsigned long long ciphertext_size);

bool encrypt(unsigned char *ciphertext, const unsigned char *key,
             const unsigned int index, const unsigned char *plaintext,
             const unsigned long long plaintext_size);

bool diffie_hellman(unsigned char *shared_secret,
                    const unsigned char *our_private_key,
                    const unsigned char *their_public_key);

bool hash(unsigned char *digest, const unsigned char *message,
          const unsigned long long message_size, const unsigned int iterations);

bool kdf(unsigned char *secret_key, const unsigned char *ikm,
         const unsigned char context);

bool sign(unsigned char *signature, const unsigned char *private_key,
          const unsigned char *message, const unsigned long long message_size);

bool verify(const unsigned char *public_key, const unsigned char *message,
            const unsigned long long message_size,
            const unsigned char *signature);

}  // namespace autograph
