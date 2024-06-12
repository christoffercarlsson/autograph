#include <string.h>

#include "autograph.h"
#include "primitives.h"

extern "C" {

size_t calculate_subject_size(const size_t data_size,
                              const size_t public_key_size) {
  size_t max_size = UINT32_MAX - public_key_size;
  size_t size = data_size > max_size ? max_size : data_size;
  return size + public_key_size;
}

void calculate_subject(uint8_t *subject, const size_t subject_size,
                       const uint8_t *public_key, const size_t public_key_size,
                       const uint8_t *data) {
  size_t key_offset = subject_size - public_key_size;
  memmove(subject, data, key_offset);
  memmove(subject + key_offset, public_key, public_key_size);
}

bool autograph_certify(uint8_t *signature, const uint8_t *our_identity_key_pair,
                       const uint8_t *their_identity_key, const uint8_t *data,
                       const size_t data_size) {
  size_t public_key_size = autograph_primitive_identity_public_key_size();
  if (data == NULL || data_size == 0) {
    return autograph_primitive_sign(signature, our_identity_key_pair,
                                    their_identity_key, public_key_size);
  }
  size_t subject_size = calculate_subject_size(data_size, public_key_size);
  uint8_t subject[subject_size];
  calculate_subject(subject, subject_size, their_identity_key, public_key_size,
                    data);
  return autograph_primitive_sign(signature, our_identity_key_pair, subject,
                                  subject_size);
}

bool autograph_verify(const uint8_t *owner_identity_key,
                      const uint8_t *certifier_identity_key,
                      const uint8_t *signature, const uint8_t *data,
                      const size_t data_size) {
  size_t public_key_size = autograph_primitive_identity_public_key_size();

  if (data == NULL || data_size == 0) {
    return autograph_primitive_verify(certifier_identity_key, signature,
                                      owner_identity_key, public_key_size);
  }
  size_t subject_size = calculate_subject_size(data_size, public_key_size);
  uint8_t subject[subject_size];
  calculate_subject(subject, subject_size, owner_identity_key, public_key_size,
                    data);
  return autograph_primitive_verify(certifier_identity_key, signature, subject,
                                    subject_size);
}

size_t autograph_signature_size() {
  return autograph_primitive_signature_size();
}

}  // extern "C"

namespace Autograph {

std::tuple<bool, Bytes> certify(const Bytes &ourIdentityKeyPair,
                                const Bytes &theirIdentityKey,
                                const std::optional<Bytes> &data) {
  Bytes signature(autograph_primitive_signature_size());
  bool success;
  if (data.has_value()) {
    success = autograph_certify(signature.data(), ourIdentityKeyPair.data(),
                                theirIdentityKey.data(), data.value().data(),
                                data.value().size());
  } else {
    success = autograph_certify(signature.data(), ourIdentityKeyPair.data(),
                                theirIdentityKey.data(), nullptr, 0);
  }
  return {success, signature};
}

bool verify(const Bytes &ownerIdentityKey, const Bytes &certifierIdentityKey,
            const Bytes &signature, const std::optional<Bytes> &data) {
  if (data.has_value()) {
    return autograph_verify(ownerIdentityKey.data(),
                            certifierIdentityKey.data(), signature.data(),
                            data.value().data(), data.value().size());
  }
  return autograph_verify(ownerIdentityKey.data(), certifierIdentityKey.data(),
                          signature.data(), nullptr, 0);
}

}  // namespace Autograph
