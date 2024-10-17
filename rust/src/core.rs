use crate::{
    auth, cert, error::Error, key_exchange as ke, key_pair, message, primitives::CorePrimitives,
};
use alloc::vec::Vec;
use rand_core::{CryptoRng, RngCore};

pub fn authenticate(
    our_identity_key_pair: &[u8],
    our_id: &[u8],
    their_identity_key: &[u8],
    their_id: &[u8],
) -> Result<Vec<u8>, Error> {
    auth::authenticate::<CorePrimitives>(
        our_identity_key_pair,
        our_id,
        their_identity_key,
        their_id,
    )
}

pub fn certify(
    our_identity_key_pair: &[u8],
    their_identity_key: &[u8],
    data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    cert::certify::<CorePrimitives>(our_identity_key_pair, their_identity_key, data)
}

pub fn verify(
    owner_identity_key: &[u8],
    certifier_identity_key: &[u8],
    signature: &[u8],
    data: Option<&[u8]>,
) -> bool {
    cert::verify::<CorePrimitives>(owner_identity_key, certifier_identity_key, signature, data)
}

#[allow(clippy::type_complexity)]
pub fn key_exchange(
    is_initiator: bool,
    our_identity_key_pair: &[u8],
    our_session_key_pair: &[u8],
    their_identity_key: &[u8],
    their_session_key: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    ke::key_exchange::<CorePrimitives>(
        is_initiator,
        our_identity_key_pair,
        our_session_key_pair,
        their_identity_key,
        their_session_key,
    )
}

pub fn verify_key_exchange(
    transcript: &[u8],
    our_identity_key_pair: &[u8],
    their_identity_key: &[u8],
    their_signature: &[u8],
) -> Result<(), Error> {
    ke::verify_key_exchange::<CorePrimitives>(
        transcript,
        our_identity_key_pair,
        their_identity_key,
        their_signature,
    )
}

pub fn generate_session_key_pair<T: RngCore + CryptoRng>(csprng: T) -> Result<Vec<u8>, Error> {
    key_pair::generate_session_key_pair::<T, CorePrimitives>(csprng)
}

pub fn generate_identity_key_pair<T: RngCore + CryptoRng>(csprng: T) -> Result<Vec<u8>, Error> {
    key_pair::generate_identity_key_pair::<T, CorePrimitives>(csprng)
}

pub fn get_identity_public_key(key_pair: &[u8]) -> Vec<u8> {
    key_pair::get_identity_public_key::<CorePrimitives>(key_pair)
}

pub fn get_session_public_key(key_pair: &[u8]) -> Vec<u8> {
    key_pair::get_session_public_key::<CorePrimitives>(key_pair)
}

pub fn get_public_keys(identity_key_pair: &[u8], session_key_pair: &[u8]) -> (Vec<u8>, Vec<u8>) {
    key_pair::get_public_keys::<CorePrimitives>(identity_key_pair, session_key_pair)
}

pub fn generate_secret_key<T: RngCore + CryptoRng>(csprng: T) -> Result<Vec<u8>, Error> {
    message::generate_secret_key::<T, CorePrimitives>(csprng)
}

pub fn create_nonce() -> Vec<u8> {
    message::create_nonce::<CorePrimitives>()
}

pub fn encrypt(key: &[u8], nonce: &mut [u8], plaintext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
    message::encrypt::<CorePrimitives>(key, nonce, plaintext)
}

pub fn decrypt(
    key: &[u8],
    nonce: &mut [u8],
    skipped_indexes: &mut [u8],
    ciphertext: &[u8],
) -> Result<(u32, Vec<u8>), Error> {
    message::decrypt::<CorePrimitives>(key, nonce, skipped_indexes, ciphertext)
}
