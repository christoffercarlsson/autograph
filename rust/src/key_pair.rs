use rand_core::{CryptoRng, RngCore};

use crate::{
    constants::{KEY_PAIR_SIZE, PRIVATE_KEY_SIZE},
    error::Error,
    external::{key_pair_identity, key_pair_session},
    types::KeyPair,
    PublicKey, PUBLIC_KEY_SIZE,
};

pub fn generate_session_key_pair<T: RngCore + CryptoRng>(csprng: T) -> Result<KeyPair, Error> {
    let mut key_pair: KeyPair = [0; KEY_PAIR_SIZE];
    if key_pair_session(csprng, &mut key_pair) {
        Ok(key_pair)
    } else {
        Err(Error::KeyPair)
    }
}

pub fn generate_identity_key_pair<T: RngCore + CryptoRng>(csprng: T) -> Result<KeyPair, Error> {
    let mut key_pair: KeyPair = [0; KEY_PAIR_SIZE];
    if key_pair_identity(csprng, &mut key_pair) {
        Ok(key_pair)
    } else {
        Err(Error::KeyPair)
    }
}

pub fn get_public_key(key_pair: &KeyPair) -> PublicKey {
    let mut public_key = [0; PUBLIC_KEY_SIZE];
    public_key.copy_from_slice(&key_pair[PRIVATE_KEY_SIZE..]);
    public_key
}

pub fn get_public_keys(
    identity_key_pair: &KeyPair,
    session_key_pair: &KeyPair,
) -> (PublicKey, PublicKey) {
    let our_identity_key = get_public_key(identity_key_pair);
    let our_session_key = get_public_key(session_key_pair);
    (our_identity_key, our_session_key)
}
