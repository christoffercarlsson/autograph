use crate::{
    error::Error,
    key_pair::get_identity_public_key,
    message::{get_uint32, set_uint32},
    primitives::{HashingPrimitive, SigningPrimitive},
};
use alloc::{vec, vec::Vec};

const FINGERPRINT_SIZE: usize = 32;
const FINGERPRINT_ITERATIONS: u16 = 5200;
const FINGERPRINT_DIVISOR: u32 = 100000;
const SAFETY_NUMBER_SIZE: usize = FINGERPRINT_SIZE * 2;

fn create_digest<P: HashingPrimitive>() -> Vec<u8> {
    vec![0; P::DIGEST_SIZE]
}

fn create_input(public_key: &[u8], id: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend(public_key);
    input.extend(id);
    input
}

fn encode_fingerprint(digest: &[u8]) -> Vec<u8> {
    let mut fingerprint = [0; FINGERPRINT_SIZE];
    for i in (0..FINGERPRINT_SIZE).step_by(4) {
        let n = get_uint32(digest, i);
        set_uint32(&mut fingerprint, i, n % FINGERPRINT_DIVISOR);
    }
    fingerprint.to_vec()
}

fn calculate_fingerprint<P: HashingPrimitive>(
    public_key: &[u8],
    id: &[u8],
) -> Result<Vec<u8>, Error> {
    if P::DIGEST_SIZE < FINGERPRINT_SIZE {
        return Err(Error::Authentication);
    }
    let input = create_input(public_key, id);
    let mut a = create_digest::<P>();
    let mut b = create_digest::<P>();
    if !P::hash(&mut a, &input) {
        return Err(Error::Authentication);
    }
    for _ in 1..FINGERPRINT_ITERATIONS {
        if !P::hash(&mut b, &a) {
            return Err(Error::Authentication);
        }
        a.copy_from_slice(&b);
    }
    Ok(encode_fingerprint(&a))
}

fn calculate_safety_number(our_fingerprint: &[u8], their_fingerprint: &[u8]) -> Vec<u8> {
    let mut safety_number = [0; SAFETY_NUMBER_SIZE];
    if their_fingerprint > our_fingerprint {
        safety_number[..FINGERPRINT_SIZE].copy_from_slice(their_fingerprint);
        safety_number[FINGERPRINT_SIZE..].copy_from_slice(our_fingerprint);
    } else {
        safety_number[..FINGERPRINT_SIZE].copy_from_slice(our_fingerprint);
        safety_number[FINGERPRINT_SIZE..].copy_from_slice(their_fingerprint);
    }
    safety_number.to_vec()
}

pub fn authenticate<P: SigningPrimitive + HashingPrimitive>(
    our_identity_key_pair: &[u8],
    our_id: &[u8],
    their_identity_key: &[u8],
    their_id: &[u8],
) -> Result<Vec<u8>, Error> {
    let our_identity_key = get_identity_public_key::<P>(our_identity_key_pair);
    let our_fingerprint = calculate_fingerprint::<P>(&our_identity_key, our_id)?;
    let their_fingerprint = calculate_fingerprint::<P>(their_identity_key, their_id)?;
    Ok(calculate_safety_number(
        &our_fingerprint,
        &their_fingerprint,
    ))
}
