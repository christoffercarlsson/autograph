use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::clib::autograph_sign_subject;
use crate::error::Error;
use crate::utils::create_signature_bytes;

pub type SignFunction = Box<dyn Fn(&Vec<u8>) -> Result<Vec<u8>, Error>>;

pub fn create_sign(identity_private_key: Vec<u8>) -> SignFunction {
    Box::new(move |subject: &Vec<u8>| {
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
            Err(Error::Signing)
        } else {
            Ok(signature)
        }
    })
}
