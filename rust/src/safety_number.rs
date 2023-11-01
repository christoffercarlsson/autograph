use crate::clib::autograph_safety_number;
use crate::types::{Bytes, SafetyNumberFunction, SafetyNumberResult};
use crate::utils::create_safety_number_bytes;
use alloc::boxed::Box;

pub fn create_safety_number<'a>(our_identity_key: &'a Bytes) -> SafetyNumberFunction {
    Box::new(|their_identity_key: &'a Bytes| -> SafetyNumberResult {
        let mut safety_number = create_safety_number_bytes();
        let success = unsafe {
            autograph_safety_number(
                safety_number.as_mut_ptr(),
                our_identity_key.as_ptr(),
                their_identity_key.as_ptr(),
            )
        } == 0;
        SafetyNumberResult {
            success,
            safety_number,
        }
    })
}
