#include "autograph/derive_secret_keys.h"

#include "autograph/diffie_hellman.h"
#include "autograph/kdf.h"

constexpr Byte CONTEXT_INITIATOR = 0x00;
constexpr Byte CONTEXT_RESPONDER = 0x01;

SecretKeys derive_secret_keys(bool is_initiator,
                              const KeyPair &our_ephemeral_key_pair,
                              const Chunk &their_ephemeral_public_key) {
  const Chunk ikm = diffie_hellman(our_ephemeral_key_pair.private_key,
                                   their_ephemeral_public_key);
  const Chunk our_secret_key =
      kdf(ikm, is_initiator ? CONTEXT_INITIATOR : CONTEXT_RESPONDER);
  const Chunk their_secret_key =
      kdf(ikm, is_initiator ? CONTEXT_RESPONDER : CONTEXT_INITIATOR);
  const SecretKeys secret_keys = {our_secret_key, their_secret_key};
  return std::move(secret_keys);
}
