use alloc::{vec, vec::Vec};

use crate::{
    constants::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE},
    error::Error,
    external::{sign, verify as verify_signature},
    types::{KeyPair, PublicKey, Signature},
};

fn create_subject(data: &[u8]) -> Vec<u8> {
    let max_size = (u32::MAX as usize) - PUBLIC_KEY_SIZE;
    let data_size = if data.len() > max_size {
        max_size
    } else {
        data.len()
    };
    vec![0; data_size + PUBLIC_KEY_SIZE]
}

fn calculate_subject(public_key: &PublicKey, data: &[u8]) -> Vec<u8> {
    let mut subject = create_subject(data);
    let key_offset = subject.len() - PUBLIC_KEY_SIZE;
    subject[..key_offset].copy_from_slice(&data[..key_offset]);
    subject[key_offset..].copy_from_slice(public_key);
    subject
}

pub fn certify(
    our_identity_key_pair: &KeyPair,
    their_identity_key: &PublicKey,
    data: Option<&[u8]>,
) -> Result<Signature, Error> {
    let mut signature = [0; SIGNATURE_SIZE];
    let subject = calculate_subject(their_identity_key, data.unwrap_or_default());
    if !sign(&mut signature, our_identity_key_pair, &subject) {
        Err(Error::Certification)
    } else {
        Ok(signature)
    }
}

pub fn verify(
    owner_identity_key: &PublicKey,
    certifier_identity_key: &PublicKey,
    signature: &Signature,
    data: Option<&[u8]>,
) -> bool {
    let subject = calculate_subject(owner_identity_key, data.unwrap_or_default());
    verify_signature(certifier_identity_key, signature, &subject)
}
