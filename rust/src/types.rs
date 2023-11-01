use crate::{
    clib::{autograph_read_uint32, autograph_read_uint64},
    utils::{create_index_bytes, create_size_bytes, create_skipped_keys_bytes},
};
use alloc::boxed::Box;
use alloc::vec::Vec;

pub enum AutographError {
    InitializationError,
}

pub type Bytes = Vec<u8>;

pub struct KeyPair {
    pub private_key: Bytes,
    pub public_key: Bytes,
}

pub struct KeyPairResult {
    pub success: bool,
    pub key_pair: KeyPair,
}

pub struct SignResult {
    pub success: bool,
    pub signature: Bytes,
}

pub struct DecryptionResult {
    pub success: bool,
    pub index: u64,
    pub data: Bytes,
}

pub struct DecryptionState {
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

pub struct EncryptionResult {
    pub success: bool,
    pub index: u64,
    pub message: Bytes,
}

pub struct EncryptionState {
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

pub type DecryptFunction<'a> = Box<dyn FnMut(&'a Bytes) -> DecryptionResult + 'a>;
pub type EncryptFunction<'a> = Box<dyn FnMut(&'a Bytes) -> EncryptionResult + 'a>;
pub type KeyExchangeVerificationFunction<'a> =
    Box<dyn FnOnce(&'a Bytes) -> KeyExchangeVerificationResult + 'a>;
pub type KeyExchangeFunction<'a> =
    Box<dyn FnMut(&mut KeyPair, &'a Bytes, &Bytes) -> KeyExchangeResult<'a> + 'a>;
pub type SafetyNumberFunction<'a> = Box<dyn Fn(&'a Bytes) -> SafetyNumberResult + 'a>;
pub type SignFunction<'a> = Box<dyn Fn(&Bytes) -> SignResult + 'a>;
pub type SignDataFunction<'a> = Box<dyn Fn(&Bytes) -> SignResult + 'a>;
pub type SignIdentityFunction<'a> = Box<dyn Fn() -> SignResult + 'a>;
pub type VerifyDataFunction<'a> = Box<dyn Fn(&Bytes, &Bytes) -> bool + 'a>;
pub type VerifyIdentityFunction<'a> = Box<dyn Fn(&Bytes) -> bool + 'a>;

pub struct Session<'a> {
    pub decrypt: DecryptFunction<'a>,
    pub encrypt: EncryptFunction<'a>,
    pub sign_data: SignDataFunction<'a>,
    pub sign_identity: SignIdentityFunction<'a>,
    pub verify_data: VerifyDataFunction<'a>,
    pub verify_identity: VerifyIdentityFunction<'a>,
}

pub struct KeyExchangeVerificationResult<'a> {
    pub success: bool,
    pub session: Session<'a>,
}

pub struct KeyExchange<'a> {
    pub handshake: Bytes,
    pub verify: KeyExchangeVerificationFunction<'a>,
}

pub struct KeyExchangeResult<'a> {
    pub success: bool,
    pub key_exchange: KeyExchange<'a>,
}

pub struct Party<'a> {
    pub calculate_safety_number: SafetyNumberFunction<'a>,
    pub perform_key_exchange: KeyExchangeFunction<'a>,
}

pub struct SafetyNumberResult {
    pub success: bool,
    pub safety_number: Bytes,
}
