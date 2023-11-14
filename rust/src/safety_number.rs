use crate::clib::autograph_safety_number;
use crate::types::{AutographError, Bytes};
use crate::utils::create_safety_number_bytes;

pub fn calculate_safety_number(a: &Bytes, b: &Bytes) -> Result<Bytes, AutographError> {
    let mut safety_number = create_safety_number_bytes();
    let success =
        unsafe { autograph_safety_number(safety_number.as_mut_ptr(), a.as_ptr(), b.as_ptr()) } == 0;
    if success {
        Ok(safety_number)
    } else {
        Err(AutographError::SafetyNumberCalculationError)
    }
}
