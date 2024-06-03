use alloc::vec::Vec;

use crate::{
    auth::authenticate,
    cert::{certify, verify},
    constants::{NONCE_SIZE, SECRET_KEY_SIZE, SKIPPED_INDEXES_COUNT, TRANSCRIPT_SIZE},
    error::Error,
    key_exchange::{key_exchange, verify_key_exchange},
    message::{decrypt, encrypt},
    types::{
        KeyPair, Nonce, PublicKey, SafetyNumber, SecretKey, Signature, SkippedIndexes, Transcript,
    },
};

pub struct Channel {
    our_identity_key_pair: KeyPair,
    our_session_key_pair: KeyPair,
    their_identity_key: PublicKey,
    their_session_key: PublicKey,
    transcript: Transcript,
    sending_key: SecretKey,
    receiving_key: SecretKey,
    sending_nonce: Nonce,
    receiving_nonce: Nonce,
    skipped_indexes: SkippedIndexes,
}

impl Channel {
    pub fn new(
        our_identity_key_pair: KeyPair,
        our_session_key_pair: KeyPair,
        their_identity_key: PublicKey,
        their_session_key: PublicKey,
    ) -> Self {
        Self {
            our_identity_key_pair,
            our_session_key_pair,
            their_identity_key,
            their_session_key,
            transcript: [0; TRANSCRIPT_SIZE],
            sending_key: [0; SECRET_KEY_SIZE],
            receiving_key: [0; SECRET_KEY_SIZE],
            sending_nonce: [0; NONCE_SIZE],
            receiving_nonce: [0; NONCE_SIZE],
            skipped_indexes: [0; SKIPPED_INDEXES_COUNT],
        }
    }

    pub fn authenticate(&self) -> Result<SafetyNumber, Error> {
        authenticate(&self.our_identity_key_pair, &self.their_identity_key)
    }

    pub fn certify(&self, data: Option<&[u8]>) -> Result<Signature, Error> {
        certify(&self.our_identity_key_pair, &self.their_identity_key, data)
    }

    pub fn verify(
        &self,
        certifier_identity_key: &PublicKey,
        signature: &Signature,
        data: Option<&[u8]>,
    ) -> bool {
        verify(
            &self.their_identity_key,
            certifier_identity_key,
            signature,
            data,
        )
    }

    pub fn key_exchange(&mut self, is_initiator: bool) -> Result<Signature, Error> {
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

    pub fn verify_key_exchange(&mut self, their_signature: &Signature) -> Result<(), Error> {
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
