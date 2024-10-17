#![no_std]

extern crate alloc;
extern crate chacha20poly1305;
extern crate ed25519_dalek;
extern crate hkdf;
extern crate rand_core;
extern crate sha2;
extern crate x25519_dalek;

mod auth;
mod cert;
mod channel;
mod core;
mod error;
mod key_exchange;
mod key_pair;
mod message;
mod primitives;

pub use channel::Channel;
pub use core::{
    authenticate, certify, create_nonce, decrypt, encrypt, generate_identity_key_pair,
    generate_secret_key, generate_session_key_pair, get_identity_public_key, get_public_keys,
    get_session_public_key, key_exchange, verify, verify_key_exchange,
};
pub use error::Error;
pub use message::create_skipped_indexes;
