use crate::clib::{
    autograph_init, autograph_key_pair_ephemeral, autograph_key_pair_identity,
    autograph_sign_subject,
};
use crate::party::create_party;
use crate::types::{
    AutographError, Bytes, KeyPair, KeyPairResult, Party, SignFunction, SignResult,
};
use crate::utils::{create_private_key_bytes, create_public_key_bytes, create_signature_bytes};
use alloc::boxed::Box;

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

    pub fn create_initiator<'a>(
        &'a self,
        sign: &'a SignFunction,
        identity_public_key: &'a Bytes,
    ) -> Party<'a> {
        create_party(true, sign, identity_public_key)
    }

    pub fn create_responder<'a>(
        &'a self,
        sign: &'a SignFunction,
        identity_public_key: &'a Bytes,
    ) -> Party<'a> {
        create_party(false, sign, identity_public_key)
    }

    pub fn create_sign<'a>(&'a self, identity_private_key: &'a Bytes) -> SignFunction {
        Box::new(|subject: &Bytes| {
            let mut signature = create_signature_bytes();
            let success = unsafe {
                autograph_sign_subject(
                    signature.as_mut_ptr(),
                    identity_private_key.as_ptr(),
                    subject.as_ptr(),
                    subject.len() as u32,
                )
            } == 0;
            SignResult { success, signature }
        })
    }

    pub fn generate_ephemeral_key_pair(&self) -> KeyPairResult {
        let mut key_pair = KeyPair {
            private_key: create_private_key_bytes(),
            public_key: create_public_key_bytes(),
        };
        let success = unsafe {
            autograph_key_pair_ephemeral(
                key_pair.private_key.as_mut_ptr(),
                key_pair.public_key.as_mut_ptr(),
            )
        } == 0;
        KeyPairResult { success, key_pair }
    }

    pub fn generate_identity_key_pair(&self) -> KeyPairResult {
        let mut key_pair = KeyPair {
            private_key: create_private_key_bytes(),
            public_key: create_public_key_bytes(),
        };
        let success = unsafe {
            autograph_key_pair_identity(
                key_pair.private_key.as_mut_ptr(),
                key_pair.public_key.as_mut_ptr(),
            )
        } == 0;
        KeyPairResult { success, key_pair }
    }
}
