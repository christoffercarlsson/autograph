use alloc::vec::Vec;

use crate::clib::{autograph_init, autograph_key_pair_ephemeral, autograph_key_pair_identity};
use crate::error::Error;
use crate::utils::{create_private_key_bytes, create_public_key_bytes};

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

pub fn generate_ephemeral_key_pair() -> Result<KeyPair, Error> {
    if unsafe { autograph_init() } < 0 {
        return Err(Error::Initialization);
    }
    let mut key_pair = KeyPair {
        private_key: create_private_key_bytes(),
        public_key: create_public_key_bytes(),
    };
    let success = unsafe {
        autograph_key_pair_ephemeral(
            key_pair.private_key.as_mut_ptr(),
            key_pair.public_key.as_mut_ptr(),
        )
    } == 0;
    if !success {
        Err(Error::KeyPairGeneration)
    } else {
        Ok(key_pair)
    }
}

pub fn generate_identity_key_pair() -> Result<KeyPair, Error> {
    if unsafe { autograph_init() } < 0 {
        return Err(Error::Initialization);
    }
    let mut key_pair = KeyPair {
        private_key: create_private_key_bytes(),
        public_key: create_public_key_bytes(),
    };
    let success = unsafe {
        autograph_key_pair_identity(
            key_pair.private_key.as_mut_ptr(),
            key_pair.public_key.as_mut_ptr(),
        )
    } == 0;
    if !success {
        Err(Error::KeyPairGeneration)
    } else {
        Ok(key_pair)
    }
}
