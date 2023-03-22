#include "autograph.h"

#include "autograph/create_key_pair.h"
#include "autograph/create_party.h"
#include "sodium.h"

Party create_alice(const KeyPair &identity_key_pair) {
  auto alice = create_party(true, identity_key_pair);
  return std::move(alice);
}

Party create_bob(const KeyPair &identity_key_pair) {
  auto bob = create_party(false, identity_key_pair);
  return std::move(bob);
}

Party create_initiator(const KeyPair &identity_key_pair) {
  auto initiator = create_alice(identity_key_pair);
  return std::move(initiator);
}

Party create_responder(const KeyPair &identity_key_pair) {
  auto responder = create_bob(identity_key_pair);
  return std::move(responder);
}

Party generate_party(bool is_initiator) {
  auto identity_key_pair = generate_key_pair();
  auto party = create_party(is_initiator, identity_key_pair);
  return std::move(party);
}

Party generate_alice() {
  auto alice = generate_party(true);
  return std::move(alice);
}

Party generate_bob() {
  auto bob = generate_party(false);
  return std::move(bob);
}

Party generate_initiator() {
  auto initiator = generate_alice();
  return std::move(initiator);
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

Party generate_responder() {
  auto responder = generate_bob();
  return std::move(responder);
}

void init() {
  if (sodium_init() != 0) {
    throw std::runtime_error("Failed to initialize libsodium");
  }
}
