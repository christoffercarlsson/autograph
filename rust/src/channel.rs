use core::marker::PhantomData;

use crate::{
    auth::authenticate,
    cert::{certify, verify},
    error::Error,
    key_exchange::{create_transcript, key_exchange, verify_key_exchange},
    key_pair::{
        create_identity_key_pair, create_identity_public_key, create_session_key_pair,
        create_session_public_key, get_identity_public_key, get_public_keys,
        get_session_public_key,
    },
    message::{create_nonce, create_secret_key, create_skipped_indexes, decrypt, encrypt},
    primitives::{
        AEADPrimitive, DiffieHellmanPrimitive, HashingPrimitive, KeyDerivationPrimitive,
        SigningPrimitive,
    },
};
use alloc::vec::Vec;

pub struct Channel<P> {
    our_identity_key_pair: Vec<u8>,
    our_session_key_pair: Vec<u8>,
    their_identity_key: Vec<u8>,
    their_session_key: Vec<u8>,
    transcript: Vec<u8>,
    sending_key: Vec<u8>,
    receiving_key: Vec<u8>,
    sending_nonce: Vec<u8>,
    receiving_nonce: Vec<u8>,
    skipped_indexes: Vec<u8>,
    _marker: PhantomData<P>,
}

impl<P: SigningPrimitive + DiffieHellmanPrimitive + AEADPrimitive> Default for Channel<P> {
    fn default() -> Self {
        Self {
            our_identity_key_pair: create_identity_key_pair::<P>(),
            our_session_key_pair: create_session_key_pair::<P>(),
            their_identity_key: create_identity_public_key::<P>(),
            their_session_key: create_session_public_key::<P>(),
            transcript: create_transcript::<P>(),
            sending_key: create_secret_key::<P>(),
            receiving_key: create_secret_key::<P>(),
            sending_nonce: create_nonce::<P>(),
            receiving_nonce: create_nonce::<P>(),
            skipped_indexes: create_skipped_indexes(None),
            _marker: PhantomData::<P>,
        }
    }
}

impl<
        P: SigningPrimitive
            + HashingPrimitive
            + DiffieHellmanPrimitive
            + KeyDerivationPrimitive
            + AEADPrimitive,
    > Channel<P>
{
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_skipped_indexes(&mut self, count: u16) {
        self.skipped_indexes = create_skipped_indexes(Some(count))
    }

    pub fn set_key_pairs(
        &mut self,
        our_identity_key_pair: &[u8],
        our_session_key_pair: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        self.our_identity_key_pair
            .copy_from_slice(our_identity_key_pair);
        self.our_session_key_pair
            .copy_from_slice(our_session_key_pair);
        get_public_keys::<P>(&self.our_identity_key_pair, &self.our_session_key_pair)
    }

    pub fn set_our_key_pairs(
        &mut self,
        our_identity_key_pair: &[u8],
        our_session_key_pair: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        self.set_key_pairs(our_identity_key_pair, our_session_key_pair)
    }

    pub fn set_public_keys(&mut self, their_identity_key: &[u8], their_session_key: &[u8]) {
        self.their_identity_key.copy_from_slice(their_identity_key);
        self.their_session_key.copy_from_slice(their_session_key);
    }

    pub fn set_their_public_keys(&mut self, their_identity_key: &[u8], their_session_key: &[u8]) {
        self.set_public_keys(their_identity_key, their_session_key);
    }

    pub fn get_our_public_keys(&self) -> (Vec<u8>, Vec<u8>) {
        get_public_keys::<P>(&self.our_identity_key_pair, &self.our_session_key_pair)
    }

    pub fn get_our_identity_key(&self) -> Vec<u8> {
        get_identity_public_key::<P>(&self.our_identity_key_pair)
    }

    pub fn get_our_session_key(&self) -> Vec<u8> {
        get_session_public_key::<P>(&self.our_session_key_pair)
    }

    pub fn get_their_public_keys(&self) -> (Vec<u8>, Vec<u8>) {
        (
            self.their_identity_key.clone(),
            self.their_session_key.clone(),
        )
    }

    pub fn get_their_identity_key(&self) -> Vec<u8> {
        self.their_identity_key.clone()
    }

    pub fn get_their_session_key(&self) -> Vec<u8> {
        self.their_session_key.clone()
    }

    pub fn authenticate(&self) -> Result<Vec<u8>, Error> {
        authenticate::<P>(&self.our_identity_key_pair, &self.their_identity_key)
    }

    pub fn certify(&self, data: Option<&[u8]>) -> Result<Vec<u8>, Error> {
        certify::<P>(&self.our_identity_key_pair, &self.their_identity_key, data)
    }

    pub fn verify(
        &self,
        certifier_identity_key: &[u8],
        signature: &[u8],
        data: Option<&[u8]>,
    ) -> bool {
        verify::<P>(
            &self.their_identity_key,
            certifier_identity_key,
            signature,
            data,
        )
    }

    pub fn key_exchange(&mut self, is_initiator: bool) -> Result<Vec<u8>, Error> {
        let result = key_exchange::<P>(
            is_initiator,
            &self.our_identity_key_pair,
            &self.our_session_key_pair,
            &self.their_identity_key,
            &self.their_session_key,
        )?;
        self.transcript.copy_from_slice(&result.transcript);
        self.sending_key.copy_from_slice(&result.sending_key);
        self.receiving_key.copy_from_slice(&result.receiving_key);
        Ok(result.signature)
    }

    pub fn verify_key_exchange(&self, their_signature: &[u8]) -> Result<(), Error> {
        verify_key_exchange::<P>(
            &self.transcript,
            &self.our_identity_key_pair,
            &self.their_identity_key,
            their_signature,
        )
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        encrypt::<P>(&self.sending_key, &mut self.sending_nonce, plaintext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(u32, Vec<u8>), Error> {
        decrypt::<P>(
            &self.receiving_key,
            &mut self.receiving_nonce,
            &mut self.skipped_indexes,
            ciphertext,
        )
    }
}
