use crate::clib::{autograph_key_pair_ephemeral, autograph_key_pair_identity};
use crate::types::{AutographError, KeyPair};
use crate::utils::{create_private_key_bytes, create_public_key_bytes};

pub fn generate_ephemeral_key_pair() -> Result<KeyPair, AutographError> {
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
        Err(AutographError::KeyPairGenerationError)
    } else {
        Ok(key_pair)
    }
}

pub fn generate_identity_key_pair() -> Result<KeyPair, AutographError> {
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
        Err(AutographError::KeyPairGenerationError)
    } else {
        Ok(key_pair)
    }
}
