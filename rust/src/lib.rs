#![no_std]

extern crate alloc;
extern crate chacha20poly1305;
extern crate ed25519_dalek;
extern crate hkdf;
extern crate rand_core;
extern crate sha2;
extern crate x25519_dalek;
extern crate zeroize;

mod auth;
mod cert;
mod channel;
mod constants;
mod error;
mod external;
mod key_exchange;
mod key_pair;
mod message;
mod types;

pub use auth::authenticate;
pub use cert::{certify, verify};
pub use channel::{use_key_pairs, Channel};
pub use constants::{
    KEY_PAIR_SIZE, NONCE_SIZE, PUBLIC_KEY_SIZE, SAFETY_NUMBER_SIZE, SECRET_KEY_SIZE,
    SIGNATURE_SIZE, TRANSCRIPT_SIZE,
};
pub use error::Error;
pub use key_exchange::{key_exchange, verify_key_exchange};
pub use key_pair::{generate_identity_key_pair, generate_session_key_pair, get_public_key};
pub use message::{decrypt, encrypt};
pub use types::{KeyPair, Nonce, PublicKey, SafetyNumber, SecretKey, Signature, Transcript};
