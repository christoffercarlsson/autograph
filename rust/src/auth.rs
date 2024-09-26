use core::mem::size_of;

use stedy::{
    ed25519_get_public_key, read_u32_be, sha512, write_u32_be, Ed25519KeyPair, Ed25519PublicKey,
    Sha512Digest, X25519PublicKey,
};

use crate::Error;

const FINGERPRINT_SIZE: usize = 32;
const FINGERPRINT_ITERATIONS: u16 = 5200;
const FINGERPRINT_DIVISOR: u32 = 100000;
pub const SAFETY_NUMBER_SIZE: usize = FINGERPRINT_SIZE * 2;

type Fingerprint = [u8; FINGERPRINT_SIZE];
pub type SafetyNumber = [u8; SAFETY_NUMBER_SIZE];

fn encode_fingerprint(digest: &Sha512Digest) -> Result<Fingerprint, Error> {
    let mut fingerprint = [0; FINGERPRINT_SIZE];
    for offset in (0..FINGERPRINT_SIZE).step_by(size_of::<u32>()) {
        let number = read_u32_be(digest, offset).or(Err(Error::Authentication))?;
        write_u32_be(&mut fingerprint, offset, number % FINGERPRINT_DIVISOR)
            .or(Err(Error::Authentication))?;
    }
    Ok(fingerprint)
}

fn calculate_fingerprint(public_key: &X25519PublicKey, id: &[u8]) -> Result<Fingerprint, Error> {
    let mut subject = public_key.to_vec();
    subject.extend_from_slice(id);
    let digest = sha512(&subject, Some(FINGERPRINT_ITERATIONS.into()));
    encode_fingerprint(&digest)
}

fn calculate_safety_number(
    our_fingerprint: &Fingerprint,
    their_fingerprint: &Fingerprint,
) -> SafetyNumber {
    let mut safety_number = [0; SAFETY_NUMBER_SIZE];
    if their_fingerprint > our_fingerprint {
        safety_number[..FINGERPRINT_SIZE].copy_from_slice(their_fingerprint);
        safety_number[FINGERPRINT_SIZE..].copy_from_slice(our_fingerprint);
    } else {
        safety_number[..FINGERPRINT_SIZE].copy_from_slice(our_fingerprint);
        safety_number[FINGERPRINT_SIZE..].copy_from_slice(their_fingerprint);
    }
    safety_number
}

pub fn authenticate(
    our_identity_key_pair: &Ed25519KeyPair,
    our_id: &[u8],
    their_identity_key: &Ed25519PublicKey,
    their_id: &[u8],
) -> Result<SafetyNumber, Error> {
    let our_identity_key = ed25519_get_public_key(our_identity_key_pair);
    let our_fingerprint = calculate_fingerprint(&our_identity_key, our_id)?;
    let their_fingerprint = calculate_fingerprint(their_identity_key, their_id)?;
    Ok(calculate_safety_number(
        &our_fingerprint,
        &their_fingerprint,
    ))
}
