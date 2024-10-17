use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead},
    ChaCha20Poly1305, KeyInit,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as ShaDigest, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

pub trait SigningPrimitive {
    const IDENTITY_PRIVATE_KEY_SIZE: usize;
    const IDENTITY_PUBLIC_KEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;

    fn key_pair_identity<T: RngCore + CryptoRng>(csprng: T, key_pair: &mut [u8]) -> bool;

    fn sign(signature: &mut [u8], key_pair: &[u8], message: &[u8]) -> bool;

    fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool;
}

pub trait DiffieHellmanPrimitive {
    const SESSION_PRIVATE_KEY_SIZE: usize;
    const SESSION_PUBLIC_KEY_SIZE: usize;
    const SHARED_SECRET_SIZE: usize;

    fn key_pair_session<T: RngCore + CryptoRng>(csprng: T, key_pair: &mut [u8]) -> bool;

    fn diffie_hellman(
        shared_secret: &mut [u8],
        our_key_pair: &[u8],
        their_public_key: &[u8],
    ) -> bool;
}

pub trait KeyDerivationPrimitive {
    fn kdf(key: &mut [u8], shared_secret: &[u8], info: &[u8]) -> bool;
}

pub trait HashingPrimitive {
    const DIGEST_SIZE: usize;

    fn hash(digest: &mut [u8], message: &[u8]) -> bool;
}

pub trait AEADPrimitive {
    const SECRET_KEY_SIZE: usize;
    const NONCE_SIZE: usize;
    const TAG_SIZE: usize;

    fn generate_key<T: RngCore + CryptoRng>(csprng: T, secret_key: &mut [u8]) -> bool;

    fn encrypt(ciphertext: &mut [u8], key: &[u8], nonce: &[u8], plaintext: &[u8]) -> bool;

    fn decrypt(plaintext: &mut [u8], key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> bool;
}

pub struct CorePrimitives;

impl SigningPrimitive for CorePrimitives {
    const IDENTITY_PRIVATE_KEY_SIZE: usize = 32;
    const IDENTITY_PUBLIC_KEY_SIZE: usize = 32;
    const SIGNATURE_SIZE: usize = 64;

    fn key_pair_identity<T: RngCore + CryptoRng>(mut csprng: T, key_pair: &mut [u8]) -> bool {
        let signing_key = SigningKey::generate(&mut csprng);
        let private_key = signing_key.to_bytes();
        let public_key = signing_key.verifying_key().to_bytes();
        key_pair[..Self::IDENTITY_PRIVATE_KEY_SIZE].copy_from_slice(&private_key);
        key_pair[Self::IDENTITY_PRIVATE_KEY_SIZE..].copy_from_slice(&public_key);
        true
    }

    fn sign(signature: &mut [u8], key_pair: &[u8], message: &[u8]) -> bool {
        let key_pair_bytes: [u8; Self::IDENTITY_PRIVATE_KEY_SIZE + Self::IDENTITY_PUBLIC_KEY_SIZE] =
            match key_pair.try_into() {
                Ok(bytes) => bytes,
                Err(_) => return false,
            };
        let key_result = SigningKey::from_keypair_bytes(&key_pair_bytes);
        if key_result.is_err() {
            return false;
        }
        let result = key_result.unwrap().try_sign(message);
        if result.is_err() {
            return false;
        }
        signature.copy_from_slice(result.unwrap().to_bytes().as_slice());
        true
    }

    fn verify(public_key: &[u8], signature: &[u8], message: &[u8]) -> bool {
        let public_key_bytes: [u8; Self::IDENTITY_PUBLIC_KEY_SIZE] = match public_key.try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let key_result = VerifyingKey::from_bytes(&public_key_bytes);
        if key_result.is_err() {
            return false;
        }
        let signature_result = Signature::from_slice(signature);
        if signature_result.is_err() {
            return false;
        }
        let verifying_key = key_result.unwrap();
        let sig = signature_result.unwrap();
        verifying_key.verify(message, &sig).is_ok()
    }
}

impl DiffieHellmanPrimitive for CorePrimitives {
    const SESSION_PRIVATE_KEY_SIZE: usize = 32;
    const SESSION_PUBLIC_KEY_SIZE: usize = 32;
    const SHARED_SECRET_SIZE: usize = 32;

    fn key_pair_session<T: RngCore + CryptoRng>(csprng: T, key_pair: &mut [u8]) -> bool {
        let secret = StaticSecret::random_from_rng(csprng);
        let private_key = secret.to_bytes();
        let dalek_public_key = PublicKey::from(&secret);
        let public_key = dalek_public_key.to_bytes();
        key_pair[..Self::SESSION_PRIVATE_KEY_SIZE].copy_from_slice(&private_key);
        key_pair[Self::SESSION_PRIVATE_KEY_SIZE..].copy_from_slice(&public_key);
        true
    }

    fn diffie_hellman(
        shared_secret: &mut [u8],
        our_key_pair: &[u8],
        their_public_key: &[u8],
    ) -> bool {
        let mut private_key = [0; Self::SESSION_PRIVATE_KEY_SIZE];
        let mut public_key = [0; Self::SESSION_PUBLIC_KEY_SIZE];
        private_key.copy_from_slice(&our_key_pair[..Self::SESSION_PRIVATE_KEY_SIZE]);
        public_key.copy_from_slice(their_public_key);
        let static_secret = StaticSecret::from(private_key);
        let public_key = PublicKey::from(public_key);
        shared_secret.copy_from_slice(
            static_secret
                .diffie_hellman(&public_key)
                .to_bytes()
                .as_slice(),
        );
        true
    }
}

impl KeyDerivationPrimitive for CorePrimitives {
    fn kdf(key: &mut [u8], shared_secret: &[u8], info: &[u8]) -> bool {
        let salt = [0; 64];
        let h = Hkdf::<Sha512>::new(Some(&salt), shared_secret);
        h.expand(info, key).is_ok()
    }
}

impl HashingPrimitive for CorePrimitives {
    const DIGEST_SIZE: usize = 64;

    fn hash(digest: &mut [u8], message: &[u8]) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(message);
        digest.copy_from_slice(hasher.finalize().to_vec().as_slice());
        true
    }
}

impl AEADPrimitive for CorePrimitives {
    const SECRET_KEY_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const TAG_SIZE: usize = 16;

    fn generate_key<T: RngCore + CryptoRng>(csprng: T, secret_key: &mut [u8]) -> bool {
        let key = ChaCha20Poly1305::generate_key(csprng);
        secret_key.copy_from_slice(&key[..Self::SECRET_KEY_SIZE]);
        true
    }

    fn encrypt(ciphertext: &mut [u8], key: &[u8], nonce: &[u8], plaintext: &[u8]) -> bool {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
        let result = cipher.encrypt(GenericArray::from_slice(nonce), plaintext.as_ref());
        if result.is_err() {
            return false;
        }
        ciphertext.copy_from_slice(result.unwrap().as_slice());
        true
    }

    fn decrypt(plaintext: &mut [u8], key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> bool {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
        let result = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext.as_ref());
        if result.is_err() {
            return false;
        }
        plaintext.copy_from_slice(result.unwrap().as_slice());
        true
    }
}
