use crate::clib::{
    autograph_decrypt, autograph_encrypt, autograph_subject, autograph_verify_data,
    autograph_verify_identity,
};
use crate::types::{Bytes, SignFunction};
use crate::utils::{
    create_ciphertext_bytes, create_index_bytes, create_plaintext_bytes, create_size_bytes,
    create_skipped_keys_bytes, create_subject_bytes, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
};
use crate::{autograph_read_uint32, autograph_read_uint64, AutographError};

struct DecryptionState {
    pub decrypt_index: Bytes,
    pub message_index: Bytes,
    pub plaintext_size: Bytes,
    pub secret_key: Bytes,
    pub skipped_keys: Bytes,
}

impl DecryptionState {
    pub fn new(secret_key: Bytes) -> Self {
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

    pub fn resize_data(&self, plaintext: &mut Bytes) {
        plaintext.truncate(self.read_plaintext_size());
    }
}

struct EncryptionState {
    pub message_index: Bytes,
    pub secret_key: Bytes,
}

impl EncryptionState {
    pub fn new(secret_key: Bytes) -> Self {
        Self {
            message_index: create_index_bytes(),
            secret_key,
        }
    }

    pub fn read_message_index(&self) -> u64 {
        unsafe { autograph_read_uint64(self.message_index.as_ptr()) }
    }
}

fn count_certificates(certificates: &Bytes) -> u32 {
    (certificates.len() / (PUBLIC_KEY_SIZE + SIGNATURE_SIZE)) as u32
}

#[non_exhaustive]
pub struct Channel<'a> {
    decrypt_state: DecryptionState,
    encrypt_state: EncryptionState,
    sign: &'a SignFunction<'a>,
    their_identity_key: &'a Bytes,
}

impl<'a> Channel<'a> {
    pub fn new(
        sign: &'a SignFunction<'a>,
        their_identity_key: &'a Bytes,
        our_secret_key: Bytes,
        their_secret_key: Bytes,
    ) -> Self {
        Self {
            decrypt_state: DecryptionState::new(their_secret_key),
            encrypt_state: EncryptionState::new(our_secret_key),
            sign,
            their_identity_key,
        }
    }

    pub fn decrypt(&mut self, message: Bytes) -> Result<(u64, Bytes), AutographError> {
        let mut data = create_plaintext_bytes(message.len());
        let success = unsafe {
            autograph_decrypt(
                data.as_mut_ptr(),
                self.decrypt_state.plaintext_size.as_mut_ptr(),
                self.decrypt_state.message_index.as_mut_ptr(),
                self.decrypt_state.decrypt_index.as_mut_ptr(),
                self.decrypt_state.skipped_keys.as_mut_ptr(),
                self.decrypt_state.secret_key.as_mut_ptr(),
                message.as_ptr(),
                message.len() as u32,
            )
        } == 0;
        if success {
            self.decrypt_state.resize_data(&mut data);
            Ok((self.decrypt_state.read_message_index(), data))
        } else {
            Err(AutographError::DecryptionError)
        }
    }

    pub fn encrypt(&mut self, plaintext: &Bytes) -> Result<(u64, Bytes), AutographError> {
        let mut ciphertext = create_ciphertext_bytes(plaintext.len());
        let success = unsafe {
            autograph_encrypt(
                ciphertext.as_mut_ptr(),
                self.encrypt_state.message_index.as_mut_ptr(),
                self.encrypt_state.secret_key.as_mut_ptr(),
                plaintext.as_ptr(),
                plaintext.len() as u32,
            )
        } == 0;
        if success {
            Ok((self.encrypt_state.read_message_index(), ciphertext))
        } else {
            Err(AutographError::EncryptionError)
        }
    }

    pub fn sign_data(&self, data: &Bytes) -> Result<Bytes, AutographError> {
        let mut subject = create_subject_bytes(data.len());
        unsafe {
            autograph_subject(
                subject.as_mut_ptr(),
                self.their_identity_key.as_ptr(),
                data.as_ptr(),
                data.len() as u32,
            );
        }
        (self.sign)(&subject)
    }

    pub fn sign_identity(&self) -> Result<Bytes, AutographError> {
        (self.sign)(self.their_identity_key)
    }

    pub fn verify_data(&self, certificates: &Bytes, data: &Bytes) -> bool {
        unsafe {
            autograph_verify_data(
                self.their_identity_key.as_ptr(),
                certificates.as_ptr(),
                count_certificates(certificates),
                data.as_ptr(),
                data.len() as u32,
            ) == 0
        }
    }

    pub fn verify_identity(&self, certificates: &Bytes) -> bool {
        unsafe {
            autograph_verify_identity(
                self.their_identity_key.as_ptr(),
                certificates.as_ptr(),
                count_certificates(certificates),
            ) == 0
        }
    }
}
