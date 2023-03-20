#include "autograph/create-session.h"

Chunk get_sign_public_key(bool is_initiator, const Chunk &transcript) {
  if (is_initiator) {
    return std::move(Chunk(transcript.begin() + 64, transcript.begin() + 96));
  } else {
    return std::move(Chunk(transcript.begin(), transcript.begin() + 32));
  }
}

DecryptFunction create_decrypt(const Chunk &their_secret_key) {
  auto decrypt_function = [&their_secret_key](const Chunk &message) {
    uint32_t index = (message[0] << 24) | (message[1] << 16) |
                     (message[2] << 8) | message[3];
    Chunk ciphertext(message.begin() + 4, message.end());
    Chunk plaintext = decrypt(their_secret_key, index, ciphertext);
    return std::move(plaintext);
  };
  return std::move(decrypt_function);
}

Chunk get_ikm(bool is_initiator, const Chunk &our_secret_key,
              const Chunk &their_secret_key) {
  Chunk ikm(our_secret_key.size() + their_secret_key.size());
  if (is_initiator) {
    std::copy(our_secret_key.begin(), our_secret_key.end(), ikm.begin());
    std::copy(their_secret_key.begin(), their_secret_key.end(),
              ikm.begin() + our_secret_key.size());
  } else {
    std::copy(their_secret_key.begin(), their_secret_key.end(), ikm.begin());
    std::copy(our_secret_key.begin(), our_secret_key.end(),
              ikm.begin() + their_secret_key.size());
  }
  return std::move(ikm);
}

DeriveKeyFunction create_derive_key(bool is_initiator,
                                    const SecretKeys &secret_keys) {
  auto derive_key_function = [is_initiator, &secret_keys]() {
    Chunk ikm = get_ikm(is_initiator, secret_keys.our_secret_key,
                        secret_keys.their_secret_key);
    Chunk secret_key = kdf(ikm, 0x00);
    return std::move(secret_key);
  };
  return std::move(derive_key_function);
}

EncryptFunction create_encrypt(const Chunk &our_secret_key) {
  uint32_t index = 0;
  auto encrypt_function = [&our_secret_key, &index](const Chunk &plaintext) {
    index++;
    Chunk ciphertext = encrypt(our_secret_key, index, plaintext);
    return std::move(ciphertext);
  };
  return std::move(encrypt_function);
}

SessionFunction create_session(bool is_initiator, const Chunk &transcript,
                               const SecretKeys &secret_keys) {
  auto session_function = [is_initiator, &transcript,
                           &secret_keys](const Chunk &ciphertext) {
    Chunk signature = decrypt(secret_keys.their_secret_key, 0, ciphertext);
    Chunk their_sign_public_key = get_sign_public_key(is_initiator, transcript);
    bool verified =
        verify_signature(their_sign_public_key, transcript, signature);
    if (!verified) {
      throw std::runtime_error("Handshake verification failed");
    }
    auto decrypt = create_decrypt(secret_keys.their_secret_key);
    auto derive_key = create_derive_key(is_initiator, secret_keys);
    auto encrypt = create_encrypt(secret_keys.our_secret_key);
    Session session = {decrypt, derive_key, encrypt};
    return std::move(session);
  };
  return std::move(session_function);
}
