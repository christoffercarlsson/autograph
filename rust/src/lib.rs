#![no_std]

extern crate alloc;

mod channel;
mod clib;
mod error;
mod key_pair;
mod safety_number;
mod sign;
mod utils;

pub use channel::Channel;
pub use clib::*;
pub use key_pair::{generate_ephemeral_key_pair, generate_identity_key_pair, KeyPair};
pub use safety_number::calculate_safety_number;
pub use sign::{create_sign, SignFunction};
