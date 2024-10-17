use alloc::{vec, vec::Vec};
use rand_core::{CryptoRng, RngCore};

use crate::{
    error::Error,
    primitives::{DiffieHellmanPrimitive, SigningPrimitive},
};

pub fn create_identity_key_pair<P: SigningPrimitive>() -> Vec<u8> {
    let size = P::IDENTITY_PRIVATE_KEY_SIZE + P::IDENTITY_PUBLIC_KEY_SIZE;
    vec![0; size]
}

pub fn create_session_key_pair<P: DiffieHellmanPrimitive>() -> Vec<u8> {
    let size = P::SESSION_PRIVATE_KEY_SIZE + P::SESSION_PUBLIC_KEY_SIZE;
    vec![0; size]
}

pub fn create_identity_public_key<P: SigningPrimitive>() -> Vec<u8> {
    vec![0; P::IDENTITY_PUBLIC_KEY_SIZE]
}

pub fn create_session_public_key<P: DiffieHellmanPrimitive>() -> Vec<u8> {
    vec![0; P::SESSION_PUBLIC_KEY_SIZE]
}

pub fn generate_session_key_pair<T: RngCore + CryptoRng, P: DiffieHellmanPrimitive>(
    csprng: T,
) -> Result<Vec<u8>, Error> {
    let mut key_pair = create_session_key_pair::<P>();
    if P::key_pair_session(csprng, &mut key_pair) {
        Ok(key_pair)
    } else {
        Err(Error::KeyPair)
    }
}

pub fn generate_identity_key_pair<T: RngCore + CryptoRng, P: SigningPrimitive>(
    csprng: T,
) -> Result<Vec<u8>, Error> {
    let mut key_pair = create_identity_key_pair::<P>();
    if P::key_pair_identity(csprng, &mut key_pair) {
        Ok(key_pair)
    } else {
        Err(Error::KeyPair)
    }
}

pub fn get_identity_public_key<P: SigningPrimitive>(key_pair: &[u8]) -> Vec<u8> {
    let mut public_key = create_identity_public_key::<P>();
    public_key.copy_from_slice(&key_pair[P::IDENTITY_PRIVATE_KEY_SIZE..]);
    public_key
}

pub fn get_session_public_key<P: DiffieHellmanPrimitive>(key_pair: &[u8]) -> Vec<u8> {
    let mut public_key = create_session_public_key::<P>();
    public_key.copy_from_slice(&key_pair[P::SESSION_PRIVATE_KEY_SIZE..]);
    public_key
}

pub fn get_public_keys<P: SigningPrimitive + DiffieHellmanPrimitive>(
    identity_key_pair: &[u8],
    session_key_pair: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let identity_key = get_identity_public_key::<P>(identity_key_pair);
    let session_key = get_session_public_key::<P>(session_key_pair);
    (identity_key, session_key)
}
