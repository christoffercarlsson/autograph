use crate::key_exchange::create_key_exchange;
use crate::safety_number::create_safety_number;
use crate::types::{Bytes, Party, SignFunction};

pub fn create_party<'a>(
    is_initiator: bool,
    sign: &'a SignFunction,
    identity_public_key: &'a Bytes,
) -> Party<'a> {
    Party {
        calculate_safety_number: create_safety_number(identity_public_key),
        perform_key_exchange: create_key_exchange(is_initiator, sign, identity_public_key),
    }
}
