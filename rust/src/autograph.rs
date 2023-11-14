use crate::clib::autograph_init;
use crate::key_exchange::perform_key_exchange;
use crate::key_pair::{generate_ephemeral_key_pair, generate_identity_key_pair};
use crate::safety_number::calculate_safety_number;
use crate::sign::create_sign;
use crate::types::{AutographError, Bytes, KeyExchangeResult, KeyPair, SignFunction};

#[non_exhaustive]
#[derive(Clone, Debug)]
pub struct Autograph;

impl Autograph {
    pub fn new() -> Result<Self, AutographError> {
        if unsafe { autograph_init() } < 0 {
            Err(AutographError::InitializationError)
        } else {
            Ok(Self)
        }
    }

    pub fn calculate_safety_number(&self, a: &Bytes, b: &Bytes) -> Result<Bytes, AutographError> {
        calculate_safety_number(a, b)
    }

    pub fn create_sign<'a>(&'a self, identity_private_key: &'a Bytes) -> SignFunction {
        create_sign(identity_private_key)
    }

    pub fn generate_ephemeral_key_pair(&self) -> Result<KeyPair, AutographError> {
        generate_ephemeral_key_pair()
    }

    pub fn generate_identity_key_pair(&self) -> Result<KeyPair, AutographError> {
        generate_identity_key_pair()
    }

    pub fn perform_key_exchange<'a>(
        &'a self,
        sign: &'a SignFunction,
        our_identity_key: &'a Bytes,
        is_initiator: bool,
        our_ephemeral_key_pair: KeyPair,
        their_identity_key: &'a Bytes,
        their_ephemeral_key: Bytes,
    ) -> KeyExchangeResult {
        perform_key_exchange(
            sign,
            our_identity_key,
            is_initiator,
            our_ephemeral_key_pair,
            their_identity_key,
            their_ephemeral_key,
        )
    }
}
