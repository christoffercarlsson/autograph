#include "autograph.h"

#include "autograph/create_party.h"
#include "autograph/generate_ephemeral_key_pair.h"

Party create_alice(const KeyPair &identity_key_pair) {
  Party alice = create_party(true, identity_key_pair);
  return std::move(alice);
}

Party create_bob(const KeyPair &identity_key_pair) {
  Party bob = create_party(false, identity_key_pair);
  return std::move(bob);
}

Party create_initiator(const KeyPair &identity_key_pair) {
  Party initiator = create_alice(identity_key_pair);
  return std::move(initiator);
}

Party create_responder(const KeyPair &identity_key_pair) {
  Party responder = create_bob(identity_key_pair);
  return std::move(responder);
}

KeyPair generate_key_pair() {
  auto key_pair = create_key_pair();
  int result = crypto_sign_keypair(key_pair.public_key.data(),
                                   key_pair.private_key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to generate Ed25519 key pair");
  }
  return std::move(key_pair);
}

void init() {
  if (sodium_init() != 0) {
    throw std::runtime_error("Failed to initialize libsodium");
  }
}
