use crate::{
    core::{authenticate, certify, decrypt, encrypt, key_exchange, verify, verify_key_exchange},
    error::Error,
    key_exchange::create_transcript,
    key_pair::{
        create_identity_key_pair, create_identity_public_key, create_session_key_pair,
        create_session_public_key,
    },
    message::{create_indexes, create_nonce, create_secret_key},
    primitives::CorePrimitives,
};
use alloc::vec::Vec;

pub struct Channel {
    our_identity_key_pair: Vec<u8>,
    our_session_key_pair: Vec<u8>,
    their_identity_key: Vec<u8>,
    their_session_key: Vec<u8>,
    transcript: Vec<u8>,
    sending_key: Vec<u8>,
    receiving_key: Vec<u8>,
    sending_nonce: Vec<u8>,
    receiving_nonce: Vec<u8>,
    skipped_indexes: Vec<u32>,
}

impl Channel {
    pub fn new(
        identity_key_pair: &[u8],
        session_key_pair: &[u8],
        identity_key: &[u8],
        session_key: &[u8],
    ) -> Self {
        let mut our_identity_key_pair = create_identity_key_pair::<CorePrimitives>();
        let mut our_session_key_pair = create_session_key_pair::<CorePrimitives>();
        let mut their_identity_key = create_identity_public_key::<CorePrimitives>();
        let mut their_session_key = create_session_public_key::<CorePrimitives>();
        our_identity_key_pair.copy_from_slice(identity_key_pair);
        our_session_key_pair.copy_from_slice(session_key_pair);
        their_identity_key.copy_from_slice(identity_key);
        their_session_key.copy_from_slice(session_key);
        Self {
            our_identity_key_pair,
            our_session_key_pair,
            their_identity_key,
            their_session_key,
            transcript: create_transcript::<CorePrimitives>(),
            sending_key: create_secret_key::<CorePrimitives>(),
            receiving_key: create_secret_key::<CorePrimitives>(),
            sending_nonce: create_nonce::<CorePrimitives>(),
            receiving_nonce: create_nonce::<CorePrimitives>(),
            skipped_indexes: create_indexes(None),
        }
    }

    pub fn authenticate(&self) -> Result<Vec<u8>, Error> {
        authenticate(&self.our_identity_key_pair, &self.their_identity_key)
    }

    pub fn certify(&self, data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        certify(&self.our_identity_key_pair, &self.their_identity_key, data)
    }

    pub fn verify(
        &self,
        certifier_identity_key: &[u8],
        signature: &[u8],
        data: Option<&[u8]>,
    ) -> bool {
        verify(
            &self.their_identity_key,
            certifier_identity_key,
            signature,
            data,
        )
    }

    pub fn key_exchange(&mut self, is_initiator: bool) -> Result<Vec<u8>, Error> {
        let (transcript, signature, sending_key, receiving_key) = key_exchange(
            is_initiator,
            &self.our_identity_key_pair,
            &self.our_session_key_pair,
            &self.their_identity_key,
            &self.their_session_key,
        )?;
        self.transcript.copy_from_slice(&transcript);
        self.sending_key.copy_from_slice(&sending_key);
        self.receiving_key.copy_from_slice(&receiving_key);
        Ok(signature)
    }

    pub fn verify_key_exchange(&self, their_signature: &[u8]) -> Result<(), Error> {
        verify_key_exchange(
            &self.transcript,
            &self.our_identity_key_pair,
            &self.their_identity_key,
            their_signature,
        )
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        encrypt(&self.sending_key, &mut self.sending_nonce, plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        decrypt(
            &self.receiving_key,
            &mut self.receiving_nonce,
            &mut self.skipped_indexes,
            ciphertext,
        )
    }
}
