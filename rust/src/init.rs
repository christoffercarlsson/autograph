use crate::clib::autograph_init;
use crate::types::AutographError;

pub fn init() -> Result<(), AutographError> {
    if unsafe { autograph_init() } < 0 {
        Err(AutographError::InitializationError)
    } else {
        Ok(())
    }
}
