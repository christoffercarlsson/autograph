use alloc::vec;
use alloc::vec::Vec;

use crate::{
    auth::authenticate,
    cert::{certify, verify},
    constants::{DEFAULT_SKIPPED_INDEXES_COUNT, NONCE_SIZE, TRANSCRIPT_SIZE},
    error::Error,
    external::zeroize,
    key_exchange::{key_exchange, verify_key_exchange},
    key_pair::get_public_key,
    message::{decrypt, encrypt},
    types::{KeyPair, Nonce, PublicKey, SafetyNumber, SecretKey, Signature, Transcript},
    KEY_PAIR_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE,
};

fn create_skipped_indexes(count: Option<u16>) -> Vec<u32> {
    let size: usize = count.unwrap_or(DEFAULT_SKIPPED_INDEXES_COUNT).into();
    vec![0; size]
}

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
    skipped_indexes: Vec<u32>,
    established: bool,
}

impl Channel {
    pub fn new(skipped_indexes_count: Option<u16>) -> Self {
        Self {
            our_identity_key_pair: [0; KEY_PAIR_SIZE],
            our_session_key_pair: [0; KEY_PAIR_SIZE],
            their_identity_key: [0; PUBLIC_KEY_SIZE],
            their_session_key: [0; PUBLIC_KEY_SIZE],
            transcript: [0; TRANSCRIPT_SIZE],
            sending_key: [0; SECRET_KEY_SIZE],
            receiving_key: [0; SECRET_KEY_SIZE],
            sending_nonce: [0; NONCE_SIZE],
            receiving_nonce: [0; NONCE_SIZE],
            skipped_indexes: create_skipped_indexes(skipped_indexes_count),
            established: false,
        }
    }

    pub fn is_established(&self) -> bool {
        self.established
    }

    pub fn use_key_pairs(
        &mut self,
        our_identity_key_pair: &KeyPair,
        our_session_key_pair: &mut KeyPair,
    ) -> Result<(PublicKey, PublicKey), Error> {
        self.established = false;
        let identity_key = get_public_key(our_identity_key_pair);
        let session_key = get_public_key(our_session_key_pair);
        self.our_identity_key_pair
            .copy_from_slice(our_identity_key_pair);
        self.our_session_key_pair
            .copy_from_slice(our_session_key_pair);
        zeroize(our_session_key_pair);
        Ok((identity_key, session_key))
    }

    pub fn use_public_keys(
        &mut self,
        their_identity_key: &PublicKey,
        their_session_key: &PublicKey,
    ) {
        self.established = false;
        self.their_identity_key.copy_from_slice(their_identity_key);
        self.their_session_key.copy_from_slice(their_session_key);
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
        self.established = false;
        let (transcript, signature, sending_key, receiving_key) = key_exchange(
            is_initiator,
            &self.our_identity_key_pair,
            &mut self.our_session_key_pair,
            &self.their_identity_key,
            &self.their_session_key,
        )?;
        self.transcript.copy_from_slice(&transcript);
        self.sending_key.copy_from_slice(&sending_key);
        self.receiving_key.copy_from_slice(&receiving_key);
        Ok(signature)
    }

    pub fn verify_key_exchange(&mut self, their_signature: &Signature) -> Result<(), Error> {
        let result = verify_key_exchange(
            &self.transcript,
            &self.our_identity_key_pair,
            &self.their_identity_key,
            their_signature,
        );
        zeroize(&mut self.sending_nonce);
        zeroize(&mut self.receiving_nonce);
        self.skipped_indexes.fill(0);
        self.established = result.is_ok();
        result
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        if self.established {
            encrypt(&self.sending_key, &mut self.sending_nonce, plaintext)
        } else {
            Err(Error::Encryption)
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        if self.established {
            decrypt(
                &self.receiving_key,
                &mut self.receiving_nonce,
                &mut self.skipped_indexes,
                ciphertext,
            )
        } else {
            Err(Error::Decryption)
        }
    }

    pub fn close(&mut self) {
        self.established = false;
        zeroize(&mut self.our_identity_key_pair);
        zeroize(&mut self.our_session_key_pair);
        zeroize(&mut self.sending_key);
        zeroize(&mut self.receiving_key);
        zeroize(&mut self.sending_nonce);
        zeroize(&mut self.receiving_nonce);
        self.skipped_indexes.fill(0);
    }
}
