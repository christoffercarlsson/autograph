use alloc::vec::Vec;

use crate::clib::{
    autograph_decrypt, autograph_encrypt, autograph_init, autograph_key_exchange_signature,
    autograph_key_exchange_transcript, autograph_key_exchange_verify, autograph_read_uint32,
    autograph_read_uint64, autograph_subject, autograph_verify_data, autograph_verify_identity,
};
use crate::error::Error;
use crate::key_pair::KeyPair;
use crate::safety_number::calculate_safety_number;
use crate::sign::SignFunction;
use crate::utils::{
    create_ciphertext_bytes, create_handshake_bytes, create_index_bytes, create_plaintext_bytes,
    create_secret_key_bytes, create_size_bytes, create_skipped_keys_bytes, create_subject_bytes,
    create_transcript_bytes, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
};

#[derive(Clone)]
pub struct DecryptionState {
    pub decrypt_index: Vec<u8>,
    pub message_index: Vec<u8>,
    pub plaintext_size: Vec<u8>,
    pub secret_key: Vec<u8>,
    pub skipped_keys: Vec<u8>,
}

impl DecryptionState {
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            decrypt_index: create_index_bytes(),
            message_index: create_index_bytes(),
            plaintext_size: create_size_bytes(),
            secret_key,
            skipped_keys: create_skipped_keys_bytes(),
        }
    }

    pub fn read_message_index(&self) -> u64 {
        unsafe { autograph_read_uint64(self.message_index.as_ptr()) }
    }

    fn read_plaintext_size(&self) -> usize {
        unsafe { autograph_read_uint32(self.plaintext_size.as_ptr()) as usize }
    }

    pub fn resize_data(&self, plaintext: &mut Vec<u8>) {
        plaintext.truncate(self.read_plaintext_size());
    }
}

#[derive(Clone)]
pub struct EncryptionState {
    pub message_index: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl EncryptionState {
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            message_index: create_index_bytes(),
            secret_key,
        }
    }

    pub fn read_message_index(&self) -> u64 {
        unsafe { autograph_read_uint64(self.message_index.as_ptr()) }
    }
}

fn count_certificates(certificates: &Vec<u8>) -> u32 {
    (certificates.len() / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)) as u32
}

#[non_exhaustive]
pub struct Channel {
    decrypt_state: Option<DecryptionState>,
    encrypt_state: Option<EncryptionState>,
    our_identity_key: Vec<u8>,
    sign: SignFunction,
    their_public_key: Option<Vec<u8>>,
    transcript: Option<Vec<u8>>,
    verified: bool,
}

impl Channel {
    pub fn new(sign: SignFunction, our_identity_key: Vec<u8>) -> Result<Self, Error> {
        if unsafe { autograph_init() } < 0 {
            Err(Error::Initialization)
        } else {
            Ok(Self {
                decrypt_state: None,
                encrypt_state: None,
                our_identity_key,
                sign,
                their_public_key: None,
                transcript: None,
                verified: false,
            })
        }
    }

    pub fn calculate_safety_number(&self) -> Result<Vec<u8>, Error> {
        if !self.is_established() {
            return Err(Error::ChannelUnestablished);
        }
        calculate_safety_number(
            &self.our_identity_key,
            self.their_public_key.as_ref().unwrap(),
        )
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if !self.is_established() {
            return Err(Error::ChannelUnestablished);
        }
        self.decrypt_state = None;
        self.encrypt_state = None;
        self.their_public_key = None;
        self.transcript = None;
        self.verified = false;
        Ok(())
    }

    pub fn decrypt(&mut self, message: Vec<u8>) -> Result<(u64, Vec<u8>), Error> {
        if !self.is_established() {
            return Err(Error::ChannelUnestablished);
        }
        let mut data = create_plaintext_bytes(message.len());
        let state = self.decrypt_state.as_mut().unwrap();
        let success = unsafe {
            autograph_decrypt(
                data.as_mut_ptr(),
                state.plaintext_size.as_mut_ptr(),
                state.message_index.as_mut_ptr(),
                state.decrypt_index.as_mut_ptr(),
                state.skipped_keys.as_mut_ptr(),
                state.secret_key.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u32,
            )
        } == 0;
        if success {
            state.resize_data(&mut data);
            Ok((state.read_message_index(), data))
        } else {
            Err(Error::Decryption)
        }
    }

    pub fn encrypt(&mut self, plaintext: &Vec<u8>) -> Result<(u64, Vec<u8>), Error> {
        if !self.is_established() {
            return Err(Error::ChannelUnestablished);
        }
        let mut ciphertext = create_ciphertext_bytes(plaintext.len());
        let state = self.encrypt_state.as_mut().unwrap();
        let success = unsafe {
            autograph_encrypt(
                ciphertext.as_mut_ptr(),
                state.message_index.as_mut_ptr(),
                state.secret_key.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len() as u32,
            )
        } == 0;
        if success {
            Ok((state.read_message_index(), ciphertext))
        } else {
            Err(Error::Encryption)
        }
    }

    pub fn is_closed(&self) -> bool {
        !(self.is_established() || self.is_initialized())
    }

    pub fn is_established(&self) -> bool {
        self.their_public_key.is_some()
            && self.decrypt_state.is_some()
            && self.encrypt_state.is_some()
            && self.transcript.is_none()
            && self.verified
    }

    pub fn is_initialized(&self) -> bool {
        self.their_public_key.is_some()
            && self.decrypt_state.is_some()
            && self.encrypt_state.is_some()
            && self.transcript.is_some()
            && !self.verified
    }

    pub fn perform_key_exchange(
        &mut self,
        is_initiator: bool,
        mut our_ephemeral_key_pair: KeyPair,
        their_identity_key: Vec<u8>,
        their_ephemeral_key: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        if self.is_established() {
            return Err(Error::ChannelAlreadyEstablished);
        }
        if self.is_initialized() {
            return Err(Error::ChannelAlreadyInitialized);
        }
        let mut handshake = create_handshake_bytes();
        let mut transcript = create_transcript_bytes();
        let mut our_secret_key = create_secret_key_bytes();
        let mut their_secret_key = create_secret_key_bytes();
        let transcript_success = unsafe {
            autograph_key_exchange_transcript(
                transcript.as_mut_ptr(),
                if is_initiator { 1 } else { 0 },
                self.our_identity_key.as_ptr(),
                our_ephemeral_key_pair.public_key.as_ptr(),
                their_identity_key.as_ptr(),
                their_ephemeral_key.as_ptr(),
            )
        } == 0;
        if !transcript_success {
            return Err(Error::KeyExchange);
        }
        let signature = (self.sign)(&transcript)?;
        let key_exchange_success = unsafe {
            autograph_key_exchange_signature(
                handshake.as_mut_ptr(),
                our_secret_key.as_mut_ptr(),
                their_secret_key.as_mut_ptr(),
                if is_initiator { 1 } else { 0 },
                signature.as_ptr(),
                our_ephemeral_key_pair.private_key.as_mut_ptr(),
                their_ephemeral_key.as_ptr(),
            )
        } == 0;
        if !key_exchange_success {
            return Err(Error::KeyExchange);
        }
        self.decrypt_state = Some(DecryptionState::new(their_secret_key));
        self.encrypt_state = Some(EncryptionState::new(our_secret_key));
        self.their_public_key = Some(their_identity_key);
        self.transcript = Some(transcript);
        self.verified = false;
        Ok(handshake)
    }

    pub fn sign_data(&self, data: &Vec<u8>) -> Result<Vec<u8>, Error> {
        if !self.is_established() {
            return Err(Error::ChannelUnestablished);
        }
        let mut subject = create_subject_bytes(data.len());
        unsafe {
            autograph_subject(
                subject.as_mut_ptr(),
                self.their_public_key.as_ref().unwrap().as_ptr(),
                data.as_ptr(),
                data.len() as u32,
            );
        }
        (self.sign)(&subject)
    }

    pub fn sign_identity(&self) -> Result<Vec<u8>, Error> {
        if !self.is_established() {
            return Err(Error::ChannelUnestablished);
        }
        (self.sign)(self.their_public_key.as_ref().unwrap())
    }

    pub fn verify_data(&self, certificates: &Vec<u8>, data: &Vec<u8>) -> Result<bool, Error> {
        if !self.is_established() {
            return Err(Error::ChannelUnestablished);
        }
        let verified = unsafe {
            autograph_verify_data(
                self.their_public_key.as_ref().unwrap().as_ptr(),
                certificates.as_ptr(),
                count_certificates(certificates),
                data.as_ptr(),
                data.len() as u32,
            )
        } == 0;
        Ok(verified)
    }

    pub fn verify_identity(&self, certificates: &Vec<u8>) -> Result<bool, Error> {
        if self.their_public_key.is_none() {
            return Err(Error::ChannelUnestablished);
        }
        let verified = unsafe {
            autograph_verify_identity(
                self.their_public_key.as_ref().unwrap().as_ptr(),
                certificates.as_ptr(),
                count_certificates(certificates),
            )
        } == 0;
        Ok(verified)
    }

    pub fn verify_key_exchange(&mut self, their_handshake: Vec<u8>) -> Result<(), Error> {
        if self.is_established() {
            return Err(Error::ChannelAlreadyEstablished);
        }
        if !self.is_initialized() {
            return Err(Error::ChannelUninitialized);
        }
        let state = self.decrypt_state.as_mut().unwrap();
        self.verified = unsafe {
            autograph_key_exchange_verify(
                self.transcript.as_ref().unwrap().as_ptr(),
                self.their_public_key.as_ref().unwrap().as_ptr(),
                state.secret_key.as_ptr(),
                their_handshake.as_ptr(),
            )
        } == 0;
        self.transcript = None;
        if !self.verified {
            return Err(Error::KeyExchangeVerification);
        }
        Ok(())
    }
}
