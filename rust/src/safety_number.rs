use alloc::vec::Vec;

use crate::clib::{autograph_init, autograph_safety_number};
use crate::error::Error;
use crate::utils::create_safety_number_bytes;

pub fn calculate_safety_number(a: &Vec<u8>, b: &Vec<u8>) -> Result<Vec<u8>, Error> {
    if unsafe { autograph_init() } < 0 {
        return Err(Error::Initialization);
    }
    let mut safety_number = create_safety_number_bytes();
    let success =
        unsafe { autograph_safety_number(safety_number.as_mut_ptr(), a.as_ptr(), b.as_ptr()) } == 0;
    if success {
        Ok(safety_number)
    } else {
        Err(Error::SafetyNumberCalculation)
    }
}
