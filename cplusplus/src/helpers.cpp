#include "autograph.h"

namespace Autograph {

void zeroize(Bytes &data) { autograph_zeroize(data.data(), data.size()); }

void zeroize(SecretKey &key) { autograph_zeroize(key.data(), key.size()); }

void zeroize(KeyPair &keyPair) {
  autograph_zeroize(keyPair.data(), keyPair.size());
}

void zeroize(Nonce &nonce) { autograph_zeroize(nonce.data(), nonce.size()); }

bool isZero(Bytes &data) { return autograph_is_zero(data.data(), data.size()); }

}  // namespace Autograph
