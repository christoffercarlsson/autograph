#pragma once

#include "autograph/types.h"

constexpr unsigned int PRIVATE_KEY_SIZE = 32;
constexpr unsigned int PUBLIC_KEY_SIZE = 32;
constexpr unsigned int SIGNATURE_SIZE = 64;

Party create_alice(const KeyPair &identity_key_pair);

Party create_bob(const KeyPair &identity_key_pair);

Party create_initiator(const KeyPair &identity_key_pair);

Party create_responder(const KeyPair &identity_key_pair);

Party generate_alice();

Party generate_bob();

Party generate_initiator();

KeyPair generate_key_pair();

Party generate_responder();

void init();
