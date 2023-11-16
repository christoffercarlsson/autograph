#![no_std]

extern crate alloc;

mod channel;
mod clib;
mod init;
mod key_exchange;
mod key_pair;
mod safety_number;
mod sign;
mod types;
mod utils;

pub use channel::{Channel, DecryptionState, EncryptionState};
pub use clib::*;
pub use init::init;
pub use key_exchange::perform_key_exchange;
pub use key_pair::{generate_ephemeral_key_pair, generate_identity_key_pair};
pub use safety_number::calculate_safety_number;
pub use sign::create_sign;
pub use types::*;
