use crate::protocol::{ChaCha20Poly1305, Ed25519Signer, Hkdf, Sha512Hasher, X25519};
use ed25519_dalek::Signer as DalekSigner;

pub struct Cipher;

impl ChaCha20Poly1305 for Cipher {
    fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: Option<&[u8]>,
        message: &mut [u8],
    ) -> [u8; 16] {
        stedy::chacha20poly1305_encrypt(key, nonce, associated_data, message)
    }

    fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        associated_data: Option<&[u8]>,
        message: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        stedy::chacha20poly1305_decrypt(key, nonce, associated_data, message, tag).is_ok()
    }
}

pub struct Hasher {
    inner: stedy::Sha512,
}

impl Sha512Hasher for Hasher {
    fn new() -> Self {
        Self {
            inner: stedy::Sha512::new(),
        }
    }

    fn update(&mut self, message: &[u8]) {
        self.inner.update(message);
    }

    fn digest(self) -> [u8; 64] {
        self.inner.finalize()
    }
}

pub struct DiffieHellman;

impl X25519 for DiffieHellman {
    fn key_pair(seed: [u8; 32]) -> ([u8; 32], [u8; 32]) {
        let private_key = x25519_dalek::StaticSecret::from(seed);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        (private_key.to_bytes(), public_key.to_bytes())
    }

    fn key_exchange(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
        let private_key = x25519_dalek::StaticSecret::from(*private_key);
        let public_key = x25519_dalek::PublicKey::from(*public_key);
        private_key.diffie_hellman(&public_key).to_bytes()
    }
}

pub struct Kdf;

impl Hkdf for Kdf {
    fn kdf(ikm: &[u8], context: &[u8]) -> [u8; 32] {
        let mut okm = [0u8; 32];
        let salt = [0u8; 64];
        stedy::hkdf_sha512(ikm, Some(&salt), Some(context), &mut okm);
        okm
    }
}

#[repr(C)]
pub struct Signer {
    private_key: [u8; 32],
    public_key: [u8; 32],
}

impl Signer {
    pub fn new(private_key: [u8; 32], public_key: [u8; 32]) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl Ed25519Signer for Signer {
    fn public_key(&self) -> Option<[u8; 32]> {
        Some(self.public_key)
    }

    fn sign(&self, message: &[u8]) -> Option<[u8; 64]> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.private_key);
        let signature: [u8; 64] = signing_key.sign(message).into();
        Some(signature)
    }

    fn verify(message: &[u8], public_key: &[u8; 32], signature: &[u8; 64]) -> bool {
        if let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) {
            let signature = ed25519_dalek::Signature::from_bytes(signature);
            verifying_key.verify_strict(message, &signature).is_ok()
        } else {
            false
        }
    }
}

impl From<[u8; 32]> for Signer {
    fn from(value: [u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&value);
        let verifying_key = signing_key.verifying_key();
        Self::new(signing_key.to_bytes(), verifying_key.to_bytes())
    }
}
