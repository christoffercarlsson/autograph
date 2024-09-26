use stedy::{
    ed25519_sign, ed25519_verify, Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, Vec,
    ED25519_PUBLIC_KEY_SIZE,
};

use crate::Error;

fn calculate_subject(public_key: &Ed25519PublicKey, data: Option<&[u8]>) -> Vec<u8> {
    let mut subject = data.unwrap_or_default().to_vec();
    let max_size = usize::MAX - ED25519_PUBLIC_KEY_SIZE;
    if subject.len() > max_size {
        subject.truncate(max_size);
    }
    subject.extend_from_slice(public_key);
    subject
}

pub fn certify(
    our_identity_key_pair: &Ed25519KeyPair,
    their_identity_key: &Ed25519PublicKey,
    data: Option<&[u8]>,
) -> Result<Ed25519Signature, Error> {
    let subject = calculate_subject(their_identity_key, data);
    ed25519_sign(our_identity_key_pair, &subject).or(Err(Error::Certification))
}

pub fn verify(
    owner_identity_key: &Ed25519PublicKey,
    certifier_identity_key: &Ed25519PublicKey,
    signature: &Ed25519Signature,
    data: Option<&[u8]>,
) -> Result<(), Error> {
    let subject = calculate_subject(owner_identity_key, data);
    ed25519_verify(certifier_identity_key, signature, &subject).or(Err(Error::Verification))
}
