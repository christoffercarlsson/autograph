use crate::protocol::{
    Aead, DiffieHellman, Digest, Hasher, IdentityKey, IdentityPrivateKey, IdentitySecretKey, Kdf,
    Nonce, PrivateKey, PublicKey, SecretKey, Seed, SharedSecret, Signature, Signer, Tag,
    DIGEST_SIZE,
};
use ed25519_dalek::Signer as DalekSigner;

pub struct ChaCha20Poly1305;

impl Aead for ChaCha20Poly1305 {
    fn encrypt(
        key: &SecretKey,
        nonce: &Nonce,
        associated_data: Option<&[u8]>,
        message: &mut [u8],
    ) -> Tag {
        stedy::chacha20poly1305_encrypt(key, nonce, associated_data, message)
    }

    fn decrypt(
        key: &SecretKey,
        nonce: &Nonce,
        associated_data: Option<&[u8]>,
        message: &mut [u8],
        tag: &Tag,
    ) -> bool {
        stedy::chacha20poly1305_decrypt(key, nonce, associated_data, message, tag).is_ok()
    }
}

pub struct X25519;

impl DiffieHellman for X25519 {
    fn calculate_key_pair(seed: Seed) -> (PrivateKey, PublicKey) {
        let private_key = x25519_dalek::StaticSecret::from(seed);
        let public_key = x25519_dalek::PublicKey::from(&private_key);
        (private_key.to_bytes(), public_key.to_bytes())
    }

    fn calculate_shared_secret(private_key: &PrivateKey, public_key: &PublicKey) -> SharedSecret {
        let private_key = x25519_dalek::StaticSecret::from(*private_key);
        let public_key = x25519_dalek::PublicKey::from(*public_key);
        private_key.diffie_hellman(&public_key).to_bytes()
    }
}

pub struct Sha512Hasher {
    inner: stedy::Sha512,
}

impl Hasher for Sha512Hasher {
    fn new() -> Self {
        Self {
            inner: stedy::Sha512::new(),
        }
    }

    fn update(&mut self, message: &[u8]) {
        self.inner.update(message);
    }

    fn finalize(self) -> Digest {
        self.inner.finalize()
    }
}

pub struct Hkdf;

impl Kdf for Hkdf {
    fn derive_key(ikm: &[u8], context: &[u8], okm: &mut [u8]) {
        stedy::hkdf_sha512(ikm, Some(&[0u8; DIGEST_SIZE]), Some(context), okm);
    }
}

pub struct Ed25519Signer {
    private_key: IdentityPrivateKey,
    public_key: IdentityKey,
}

impl Ed25519Signer {
    pub fn new(private_key: IdentityPrivateKey, public_key: IdentityKey) -> Self {
        Self {
            private_key,
            public_key,
        }
    }
}

impl Signer for Ed25519Signer {
    fn from_bytes(secret: IdentitySecretKey) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
        let verifying_key = signing_key.verifying_key();
        Self::new(signing_key.to_bytes(), verifying_key.to_bytes())
    }

    fn get_identity_key(&self) -> Option<IdentityKey> {
        Some(self.public_key)
    }

    fn sign(&self, subject: &[u8]) -> Option<Signature> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&self.private_key);
        let signature: Signature = signing_key.sign(subject).into();
        Some(signature)
    }

    fn verify(subject: &[u8], public_key: &IdentityKey, signature: &Signature) -> bool {
        if let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) {
            let signature = ed25519_dalek::Signature::from_bytes(signature);
            verifying_key.verify_strict(subject, &signature).is_ok()
        } else {
            false
        }
    }
}

pub struct Ed25519Verifier;

impl Signer for Ed25519Verifier {
    #[allow(unused_variables)]
    fn from_bytes(secret: IdentitySecretKey) -> Self {
        Self
    }

    fn get_identity_key(&self) -> Option<IdentityKey> {
        None
    }

    #[allow(unused_variables)]
    fn sign(&self, subject: &[u8]) -> Option<Signature> {
        None
    }

    fn verify(subject: &[u8], public_key: &IdentityKey, signature: &Signature) -> bool {
        Ed25519Signer::verify(subject, public_key, signature)
    }
}
