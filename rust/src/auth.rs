use crate::{
    constants::{
        DIGEST_SIZE, FINGERPRINT_DIVISOR, FINGERPRINT_ITERATIONS, FINGERPRINT_SIZE,
        SAFETY_NUMBER_SIZE,
    },
    error::Error,
    external::hash,
    key_pair::get_public_key,
    support::{get_uint32, set_uint32},
    types::{Digest, Fingerprint, PublicKey, SafetyNumber},
    KeyPair,
};

fn encode_fingerprint(digest: &Digest) -> Fingerprint {
    let mut fingerprint = [0; FINGERPRINT_SIZE];
    for i in (0..FINGERPRINT_SIZE).step_by(4) {
        let n = get_uint32(digest, i);
        set_uint32(&mut fingerprint, i, n % FINGERPRINT_DIVISOR);
    }
    fingerprint
}

fn calculate_fingerprint(public_key: &PublicKey) -> Result<Fingerprint, Error> {
    let mut a = [0; DIGEST_SIZE];
    let mut b = [0; DIGEST_SIZE];
    if !hash(&mut a, public_key) {
        return Err(Error::Authentication);
    }
    for _ in 1..FINGERPRINT_ITERATIONS {
        if !hash(&mut b, &a) {
            return Err(Error::Authentication);
        }
        a.copy_from_slice(&b);
    }
    Ok(encode_fingerprint(&a))
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
    our_identity_key_pair: &KeyPair,
    their_identity_key: &PublicKey,
) -> Result<SafetyNumber, Error> {
    let our_identity_key = get_public_key(our_identity_key_pair);
    let our_fingerprint = calculate_fingerprint(&our_identity_key)?;
    let their_fingerprint = calculate_fingerprint(their_identity_key)?;
    Ok(calculate_safety_number(
        &our_fingerprint,
        &their_fingerprint,
    ))
}
