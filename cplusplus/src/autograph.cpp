#include "autograph.h"

#include "autograph/autograph_init.h"
#include "autograph/create_calculate_safety_number.h"
#include "autograph/create_handshake.h"
#include "autograph/generate_key_pair.h"

KeyPair create_key_pair() {
  KeyPair key_pair;
  key_pair.public_key = Chunk(PUBLIC_KEY_SIZE);
  key_pair.private_key = Chunk(PRIVATE_KEY_SIZE);
  return std::move(key_pair);
}

KeyPair generate_session_key_pair() {
  auto key_pair = create_key_pair();
  bool success = generate_ephemeral_key_pair(key_pair.public_key.data(),
                                             key_pair.private_key.data());
  if (!success) {
    throw std::runtime_error("Failed to generate ephemeral key pair");
  }
  return std::move(key_pair);
}

Party create_party(bool is_initiator, const KeyPair &identity_key_pair) {
  auto ephemeral_key_pair = generate_session_key_pair();
  auto calculate_safety_number =
      create_calculate_safety_number(identity_key_pair.public_key);
  auto handshake =
      create_handshake(is_initiator, identity_key_pair, ephemeral_key_pair);
  Party party = {
      calculate_safety_number,
      ephemeral_key_pair.public_key,
      handshake,
      identity_key_pair.public_key,
  };
  return std::move(party);
}

KeyPair generate_key_pair() {
  auto key_pair = create_key_pair();
  bool success = generate_identity_key_pair(key_pair.public_key.data(),
                                            key_pair.private_key.data());
  if (!success) {
    throw std::runtime_error("Failed to generate identity key pair");
  }
  return std::move(key_pair);
}

Party generate_party(bool is_initiator) {
  auto identity_key_pair = generate_key_pair();
  auto party = create_party(is_initiator, identity_key_pair);
  return std::move(party);
}

void init() {
  bool success = autograph_init();
  if (!success) {
    throw std::runtime_error("Failed to initialize Autograph");
  }
}
