#include "autograph/derive_secret_keys.h"

SecretKeys derive_secret_keys(bool is_initiator,
                              const KeyPair &our_ephemeral_key_pair,
                              const Chunk &their_ephemeral_public_key) {
  const Chunk ikm = diffie_hellman(our_ephemeral_key_pair.private_key,
                                   their_ephemeral_public_key);
  const Chunk our_secret_key = kdf(ikm, is_initiator ? 0x00 : 0x01);
  const Chunk their_secret_key = kdf(ikm, is_initiator ? 0x01 : 0x00);
  const SecretKeys secret_keys = {our_secret_key, their_secret_key};
  return std::move(secret_keys);
}
