use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::channel::Channel;

#[derive(Debug)]
pub enum AutographError {
    DecryptionError,
    EncryptionError,
    InitializationError,
    KeyExchangeError,
    KeyExchangeVerificationError,
    KeyPairGenerationError,
    SafetyNumberCalculationError,
    SigningError,
}

pub type Bytes = Vec<u8>;

pub type KeyExchangeResult<'a> =
    Result<(Bytes, KeyExchangeVerificationFunction<'a>), AutographError>;

pub type KeyExchangeVerificationFunction<'a> =
    Box<dyn FnOnce(Bytes) -> Result<Channel<'a>, AutographError> + 'a>;

#[derive(Clone, Debug)]
pub struct KeyPair {
    pub private_key: Bytes,
    pub public_key: Bytes,
}

pub type SignFunction<'a> = Box<dyn Fn(&Bytes) -> Result<Bytes, AutographError> + 'a>;
