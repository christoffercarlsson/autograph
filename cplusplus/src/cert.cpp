#include "autograph.h"

namespace Autograph {

tuple<bool, Signature> certify(const KeyPair &ourIdentityKeyPair,
                               const PublicKey &theirIdentityKey,
                               const optional<Bytes> &data) {
  Signature signature;
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

bool verify(const PublicKey &ownerIdentityKey,
            const PublicKey &certifierIdentityKey, const Signature &signature,
            const optional<Bytes> &data) {
  if (data.has_value()) {
    return autograph_verify(ownerIdentityKey.data(),
                            certifierIdentityKey.data(), signature.data(),
                            data.value().data(), data.value().size());
  }
  return autograph_verify(ownerIdentityKey.data(), certifierIdentityKey.data(),
                          signature.data(), nullptr, 0);
}

}  // namespace Autograph
