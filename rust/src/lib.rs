#![no_std]

extern crate stedy;

#[derive(Debug)]
pub enum Error {
    Authentication,
    Certification,
    Verification,
    Decryption,
    Encryption,
    KeyDerivation,
    KeyExchange,
    Message,
    MissingKeyPairs,
    MissingPublicKeys,
    MissingSecretKeys,
    KeyPairsAlreadySet,
    PublicKeysAlreadySet,
}

mod auth;
mod cert;
mod channel;
mod kdf;
mod key_exchange;
mod message;
mod state;

pub use stedy::{
    chacha20poly1305_generate_key as generate_secret_key,
    ed25519_generate_key_pair as generate_identity_key_pair,
    ed25519_get_private_key as get_identity_private_key,
    ed25519_get_public_key as get_identity_public_key,
    x25519_generate_key_pair as generate_session_key_pair,
    x25519_get_private_key as get_session_private_key,
    x25519_get_public_key as get_session_public_key, ChaCha20Poly1305Key, ChaCha20Poly1305Nonce,
    Ed25519KeyPair, Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, X25519KeyPair,
    X25519PrivateKey, X25519PublicKey, CHACHA20_POLY1305_KEY_SIZE, CHACHA20_POLY1305_NONCE_SIZE,
    ED25519_KEY_PAIR_SIZE, ED25519_PRIVATE_KEY_SIZE, ED25519_PUBLIC_KEY_SIZE,
    ED25519_SIGNATURE_SIZE, X25519_KEY_PAIR_SIZE, X25519_PRIVATE_KEY_SIZE, X25519_PUBLIC_KEY_SIZE,
};

pub use auth::{authenticate, SafetyNumber, SAFETY_NUMBER_SIZE};
pub use cert::{certify, verify};
pub use channel::Channel;
pub use kdf::derive_key;
pub use key_exchange::{key_exchange, verify_key_exchange};
pub use message::{decrypt, encrypt};
