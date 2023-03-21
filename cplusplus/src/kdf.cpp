#include "autograph/kdf.h"

#include "sodium.h"

Chunk hmac_sha512(const Chunk &key, const Chunk &data) {
  Chunk digest(crypto_auth_hmacsha512_BYTES);
  int result = crypto_auth_hmacsha512(digest.data(), data.data(), data.size(),
                                      key.data());
  if (result != 0) {
    throw std::runtime_error("Failed to hash message");
  }
  return std::move(digest);
}

Chunk hkdf_extract(const Chunk &ikm, const Chunk &salt) {
  Chunk prk = hmac_sha512(salt, ikm);
  return std::move(prk);
}

Chunk hkdf_expand(const Chunk &prk, const Chunk &info, unsigned int length) {
  Chunk okm;
  Chunk tmp;
  unsigned int i = 0;
  while (okm.size() < length) {
    i += 1;
    Chunk data;
    data.insert(data.end(), tmp.begin(), tmp.end());
    data.insert(data.end(), info.begin(), info.end());
    data.push_back(i & 0xFF);
    tmp = hmac_sha512(prk, data);
    okm.insert(okm.end(), tmp.begin(), tmp.end());
  }
  okm.resize(length);
  return std::move(okm);
}

Chunk kdf(const Chunk &ikm, const Byte context) {
  Chunk salt(crypto_auth_hmacsha512_BYTES, 0x00);
  Chunk info(1, context);
  Chunk prk = hkdf_extract(ikm, salt);
  Chunk okm = hkdf_expand(prk, info, crypto_aead_aes256gcm_KEYBYTES);
  return std::move(okm);
}
