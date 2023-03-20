#include "autograph/derive_secret_keys.h"

Chunk derive_shared_secrets(bool is_initiator, const Chunk &our_private_key,
                            const Chunk &our_ephemeral_private_key,
                            const Chunk &their_identity,
                            const Chunk &their_ephemeral_public_key) {
  const Chunk their_public_key(their_identity.end() - crypto_box_PUBLICKEYBYTES,
                               their_identity.end());
  Chunk a = diffie_hellman(our_private_key, their_ephemeral_public_key);
  Chunk b = diffie_hellman(our_ephemeral_private_key, their_public_key);
  if (is_initiator) {
    a.insert(a.end(), b.begin(), b.end());
    return std::move(a);
  }
  b.insert(b.end(), a.begin(), a.end());
  return std::move(b);
}

SecretKeys derive_secret_keys(bool is_initiator, const KeyPair &our_key_pair,
                              const KeyPair &our_ephemeral_key_pair,
                              const Chunk &their_identity,
                              const Chunk &their_ephemeral_public_key) {
  const Chunk ikm =
      derive_shared_secrets(is_initiator, our_key_pair.private_key,
                            our_ephemeral_key_pair.private_key, their_identity,
                            their_ephemeral_public_key);
  const Chunk our_secret_key = kdf(ikm, is_initiator ? 0x00 : 0x01);
  const Chunk their_secret_key = kdf(ikm, is_initiator ? 0x01 : 0x00);
  const SecretKeys secret_keys = {our_secret_key, their_secret_key};
  return std::move(secret_keys);
}
