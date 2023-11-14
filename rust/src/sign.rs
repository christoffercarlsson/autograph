use alloc::boxed::Box;

use crate::clib::autograph_sign_subject;
use crate::types::{AutographError, Bytes, SignFunction};
use crate::utils::create_signature_bytes;

pub fn create_sign(identity_private_key: &Bytes) -> SignFunction {
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
        if !success {
            Err(AutographError::SigningError)
        } else {
            Ok(signature)
        }
    })
}
