use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead},
    ChaCha20Poly1305, KeyInit,
};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as ShaDigest, Sha512};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::{
    constants::PRIVATE_KEY_SIZE,
    types::{Digest, KeyPair, Nonce, PrivateKey, PublicKey, SecretKey, SharedSecret, Signature},
};

pub fn encrypt(ciphertext: &mut [u8], key: &SecretKey, nonce: &Nonce, plaintext: &[u8]) -> bool {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let result = cipher.encrypt(GenericArray::from_slice(nonce), plaintext.as_ref());
    if result.is_err() {
        return false;
    }
    ciphertext.copy_from_slice(result.unwrap().as_slice());
    true
}

pub fn decrypt(plaintext: &mut [u8], key: &SecretKey, nonce: &Nonce, ciphertext: &[u8]) -> bool {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    let result = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext.as_ref());
    if result.is_err() {
        return false;
    }
    plaintext.copy_from_slice(result.unwrap().as_slice());
    true
}

pub fn diffie_hellman(
    shared_secret: &mut SharedSecret,
    our_key_pair: &KeyPair,
    their_public_key: &PublicKey,
) -> bool {
    let mut our_private_key = [0; PRIVATE_KEY_SIZE];
    our_private_key.copy_from_slice(&our_key_pair[..PRIVATE_KEY_SIZE]);
    let mut static_secret = StaticSecret::from(our_private_key);
    let public_key = DalekPublicKey::from(*their_public_key);
    shared_secret.copy_from_slice(
        static_secret
            .diffie_hellman(&public_key)
            .to_bytes()
            .as_slice(),
    );
    our_private_key.zeroize();
    static_secret.zeroize();
    true
}

fn create_key_pair(key_pair: &mut KeyPair, mut private_key: PrivateKey, public_key: PublicKey) {
    key_pair[..PRIVATE_KEY_SIZE].copy_from_slice(&private_key);
    key_pair[PRIVATE_KEY_SIZE..].copy_from_slice(&public_key);
    private_key.zeroize();
}

pub fn key_pair_session<T: RngCore + CryptoRng>(csprng: T, key_pair: &mut KeyPair) -> bool {
    let mut secret = StaticSecret::random_from_rng(csprng);
    let public_key = DalekPublicKey::from(&secret);
    create_key_pair(key_pair, secret.to_bytes(), public_key.to_bytes());
    secret.zeroize();
    true
}

pub fn key_pair_identity<T: RngCore + CryptoRng>(mut csprng: T, key_pair: &mut KeyPair) -> bool {
    let signing_key = SigningKey::generate(&mut csprng);
    create_key_pair(
        key_pair,
        signing_key.to_bytes(),
        signing_key.verifying_key().to_bytes(),
    );
    true
}

pub fn sign(signature: &mut Signature, key_pair: &KeyPair, message: &[u8]) -> bool {
    let key_result = SigningKey::from_keypair_bytes(key_pair);
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

pub fn verify(public_key: &PublicKey, signature: &Signature, message: &[u8]) -> bool {
    let key_result = VerifyingKey::from_bytes(public_key);
    if key_result.is_err() {
        return false;
    }
    let signature_result = DalekSignature::from_slice(signature);
    if signature_result.is_err() {
        return false;
    }
    let verifying_key = key_result.unwrap();
    let sig = signature_result.unwrap();
    verifying_key.verify(message, &sig).is_ok()
}

pub fn hash(digest: &mut Digest, message: &[u8]) -> bool {
    let mut hasher = Sha512::new();
    hasher.update(message);
    digest.copy_from_slice(hasher.finalize().to_vec().as_slice());
    true
}

pub fn hkdf(okm: &mut [u8], ikm: &[u8], salt: &[u8], info: &[u8]) -> bool {
    let h = Hkdf::<Sha512>::new(Some(salt), ikm);
    h.expand(info, okm).is_ok()
}

pub fn get_uint32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub fn set_uint32(bytes: &mut [u8], offset: usize, number: u32) {
    bytes[offset..offset + 4].copy_from_slice(number.to_be_bytes().as_slice());
}
