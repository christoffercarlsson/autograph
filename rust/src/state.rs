use stedy::{
    ed25519_get_public_key, is_zero, x25519_get_public_key, zeroize, ChaCha20Poly1305Key,
    ChaCha20Poly1305Nonce, Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, Vec, X25519KeyPair,
    X25519PublicKey, CHACHA20_POLY1305_KEY_SIZE, CHACHA20_POLY1305_NONCE_SIZE,
    ED25519_KEY_PAIR_SIZE, ED25519_PUBLIC_KEY_SIZE, X25519_KEY_PAIR_SIZE, X25519_PUBLIC_KEY_SIZE,
};

use crate::{
    authenticate, certify, decrypt, encrypt, key_exchange, verify, verify_key_exchange, Error,
    SafetyNumber,
};

pub struct State {
    pub our_identity_key_pair: Ed25519KeyPair,
    pub our_session_key_pair: X25519KeyPair,
    pub their_identity_key: Ed25519PublicKey,
    pub their_session_key: X25519PublicKey,
    pub sending_key: ChaCha20Poly1305Key,
    pub receiving_key: ChaCha20Poly1305Key,
    pub sending_nonce: ChaCha20Poly1305Nonce,
}

pub fn create_state() -> State {
    State {
        our_identity_key_pair: [0; ED25519_KEY_PAIR_SIZE],
        our_session_key_pair: [0; X25519_KEY_PAIR_SIZE],
        their_identity_key: [0; ED25519_PUBLIC_KEY_SIZE],
        their_session_key: [0; X25519_PUBLIC_KEY_SIZE],
        sending_key: [0; CHACHA20_POLY1305_KEY_SIZE],
        receiving_key: [0; CHACHA20_POLY1305_KEY_SIZE],
        sending_nonce: [0; CHACHA20_POLY1305_NONCE_SIZE],
    }
}

fn has_key_pairs(state: &State) -> bool {
    !is_zero(&state.our_identity_key_pair) && !is_zero(&state.our_session_key_pair)
}

fn has_public_keys(state: &State) -> bool {
    !is_zero(&state.their_identity_key) && !is_zero(&state.their_session_key)
}

fn has_secret_keys(state: &State) -> bool {
    !is_zero(&state.sending_key) && !is_zero(&state.receiving_key)
}

fn ensure_init(state: &State) -> Result<(), Error> {
    if !has_key_pairs(state) {
        return Err(Error::MissingKeyPairs);
    }
    if !has_public_keys(state) {
        return Err(Error::MissingPublicKeys);
    }
    Ok(())
}

fn ensure_established(state: &State) -> Result<(), Error> {
    ensure_init(state)?;
    if !has_secret_keys(state) {
        return Err(Error::MissingSecretKeys);
    }
    Ok(())
}

pub fn set_key_pairs(
    state: &mut State,
    our_identity_key_pair: &Ed25519KeyPair,
    our_session_key_pair: &X25519KeyPair,
) -> Result<(Ed25519PublicKey, X25519PublicKey), Error> {
    if has_key_pairs(state) {
        return Err(Error::KeyPairsAlreadySet);
    }
    state
        .our_identity_key_pair
        .copy_from_slice(our_identity_key_pair);
    state
        .our_session_key_pair
        .copy_from_slice(our_session_key_pair);
    let identity_key = ed25519_get_public_key(our_identity_key_pair);
    let session_key = x25519_get_public_key(our_session_key_pair);
    Ok((identity_key, session_key))
}

pub fn set_public_keys(
    state: &mut State,
    their_identity_key: &Ed25519PublicKey,
    their_session_key: &X25519PublicKey,
) -> Result<(), Error> {
    if !has_public_keys(state) {
        state.their_identity_key.copy_from_slice(their_identity_key);
        state.their_session_key.copy_from_slice(their_session_key);
        Ok(())
    } else {
        Err(Error::PublicKeysAlreadySet)
    }
}

pub fn get_identity_key(state: &State) -> Result<Ed25519PublicKey, Error> {
    if has_key_pairs(state) {
        let identity_key = ed25519_get_public_key(&state.our_identity_key_pair);
        Ok(identity_key)
    } else {
        Err(Error::MissingKeyPairs)
    }
}

pub fn get_session_key(state: &State) -> Result<X25519PublicKey, Error> {
    if has_key_pairs(state) {
        let session_key = x25519_get_public_key(&state.our_session_key_pair);
        Ok(session_key)
    } else {
        Err(Error::MissingKeyPairs)
    }
}

pub fn get_their_identity_key(state: &State) -> Result<Ed25519PublicKey, Error> {
    if has_public_keys(state) {
        Ok(state.their_identity_key)
    } else {
        Err(Error::MissingPublicKeys)
    }
}

pub fn get_their_session_key(state: &State) -> Result<X25519PublicKey, Error> {
    if has_public_keys(state) {
        Ok(state.their_session_key)
    } else {
        Err(Error::MissingPublicKeys)
    }
}

pub fn state_authenticate(
    state: &State,
    our_id: &[u8],
    their_id: &[u8],
) -> Result<SafetyNumber, Error> {
    ensure_init(state)?;
    authenticate(
        &state.our_identity_key_pair,
        our_id,
        &state.their_identity_key,
        their_id,
    )
}

pub fn state_certify(state: &State, data: Option<&[u8]>) -> Result<Ed25519Signature, Error> {
    ensure_init(state)?;
    certify(
        &state.our_identity_key_pair,
        &state.their_identity_key,
        data,
    )
}

pub fn state_verify(
    state: &State,
    certifier_identity_key: &Ed25519PublicKey,
    signature: &Ed25519Signature,
    data: Option<&[u8]>,
) -> Result<(), Error> {
    ensure_init(state)?;
    verify(
        &state.their_identity_key,
        certifier_identity_key,
        signature,
        data,
    )
}

pub fn state_key_exchange(state: &mut State) -> Result<Ed25519Signature, Error> {
    ensure_init(state)?;
    let (signature, mut sending_key, mut receiving_key) = key_exchange(
        &state.our_identity_key_pair,
        &state.our_session_key_pair,
        &state.their_identity_key,
        &state.their_session_key,
    )?;
    state.sending_key.copy_from_slice(&sending_key);
    state.receiving_key.copy_from_slice(&receiving_key);
    zeroize(&mut sending_key);
    zeroize(&mut receiving_key);
    Ok(signature)
}

pub fn state_verify_key_exchange(state: &State, signature: &Ed25519Signature) -> Result<(), Error> {
    ensure_init(state)?;
    verify_key_exchange(
        &state.our_identity_key_pair,
        &state.our_session_key_pair,
        &state.their_identity_key,
        &state.their_session_key,
        signature,
    )
}

pub fn state_encrypt(state: &mut State, plaintext: &[u8]) -> Result<(u64, Vec<u8>), Error> {
    ensure_established(state)?;
    encrypt(&state.sending_key, &mut state.sending_nonce, plaintext)
}

pub fn state_decrypt(state: &State, ciphertext: &[u8]) -> Result<(u64, Vec<u8>), Error> {
    ensure_established(state)?;
    decrypt(&state.receiving_key, ciphertext)
}
