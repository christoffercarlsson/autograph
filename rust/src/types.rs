use alloc::boxed::Box;
use alloc::vec::Vec;

#[derive(Debug)]
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

pub struct EncryptionResult {
    pub success: bool,
    pub index: u64,
    pub message: Bytes,
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
