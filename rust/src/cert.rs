use alloc::{vec, vec::Vec};

use crate::{error::Error, primitives::SigningPrimitive};

fn create_subject<P: SigningPrimitive>(data: &[u8]) -> Vec<u8> {
    let max_size = (u32::MAX as usize) - P::IDENTITY_PUBLIC_KEY_SIZE;
    let data_size = if data.len() > max_size {
        max_size
    } else {
        data.len()
    };
    vec![0; data_size + P::IDENTITY_PUBLIC_KEY_SIZE]
}

fn calculate_subject<P: SigningPrimitive>(public_key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut subject = create_subject::<P>(data);
    let key_offset = subject.len() - P::IDENTITY_PUBLIC_KEY_SIZE;
    subject[..key_offset].copy_from_slice(&data[..key_offset]);
    subject[key_offset..].copy_from_slice(public_key);
    subject
}

fn create_signature<P: SigningPrimitive>() -> Vec<u8> {
    vec![0; P::SIGNATURE_SIZE]
}

pub fn certify<P: SigningPrimitive>(
    our_identity_key_pair: &[u8],
    their_identity_key: &[u8],
    data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut signature = create_signature::<P>();
    let subject = calculate_subject::<P>(their_identity_key, data.unwrap_or_default());
    if !P::sign(&mut signature, our_identity_key_pair, &subject) {
        Err(Error::Certification)
    } else {
        Ok(signature)
    }
}

pub fn verify<P: SigningPrimitive>(
    owner_identity_key: &[u8],
    certifier_identity_key: &[u8],
    signature: &[u8],
    data: Option<&[u8]>,
) -> bool {
    let subject = calculate_subject::<P>(owner_identity_key, data.unwrap_or_default());
    P::verify(certifier_identity_key, signature, &subject)
}
