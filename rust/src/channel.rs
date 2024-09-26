use stedy::{
    Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, Vec, X25519KeyPair, X25519PublicKey,
};

use crate::{
    state::{
        create_state, get_identity_key, get_session_key, get_their_identity_key,
        get_their_session_key, set_key_pairs, set_public_keys, state_authenticate, state_certify,
        state_decrypt, state_encrypt, state_key_exchange, state_verify, state_verify_key_exchange,
        State,
    },
    Error, SafetyNumber,
};

pub struct Channel {
    state: State,
}

impl Channel {
    pub fn new() -> Self {
        Self {
            state: create_state(),
        }
    }

    pub fn set_key_pairs(
        &mut self,
        our_identity_key_pair: &Ed25519KeyPair,
        our_session_key_pair: &X25519KeyPair,
    ) -> Result<(Ed25519PublicKey, X25519PublicKey), Error> {
        set_key_pairs(&mut self.state, our_identity_key_pair, our_session_key_pair)
    }

    pub fn set_public_keys(
        &mut self,
        their_identity_key: &Ed25519PublicKey,
        their_session_key: &X25519PublicKey,
    ) -> Result<(), Error> {
        set_public_keys(&mut self.state, their_identity_key, their_session_key)
    }

    pub fn get_identity_key(&self) -> Result<Ed25519PublicKey, Error> {
        get_identity_key(&self.state)
    }

    pub fn get_session_key(&self) -> Result<X25519PublicKey, Error> {
        get_session_key(&self.state)
    }

    pub fn get_their_identity_key(&self) -> Result<Ed25519PublicKey, Error> {
        get_their_identity_key(&self.state)
    }

    pub fn get_their_session_key(&self) -> Result<X25519PublicKey, Error> {
        get_their_session_key(&self.state)
    }

    pub fn authenticate(&self, our_id: &[u8], their_id: &[u8]) -> Result<SafetyNumber, Error> {
        state_authenticate(&self.state, our_id, their_id)
    }

    pub fn certify(&self, data: Option<&[u8]>) -> Result<Ed25519Signature, Error> {
        state_certify(&self.state, data)
    }

    pub fn verify(
        &self,
        certifier_identity_key: &Ed25519PublicKey,
        signature: &Ed25519Signature,
        data: Option<&[u8]>,
    ) -> Result<(), Error> {
        state_verify(&self.state, certifier_identity_key, signature, data)
    }

    pub fn key_exchange(&mut self) -> Result<Ed25519Signature, Error> {
        state_key_exchange(&mut self.state)
    }

    pub fn verify_key_exchange(&self, their_signature: &Ed25519Signature) -> Result<(), Error> {
        state_verify_key_exchange(&self.state, their_signature)
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), Error> {
        state_encrypt(&mut self.state, plaintext)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<(u64, Vec<u8>), Error> {
        state_decrypt(&self.state, ciphertext)
    }
}

impl Default for Channel {
    fn default() -> Self {
        Self::new()
    }
}
