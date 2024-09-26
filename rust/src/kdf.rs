use stedy::hkdf_sha512;

use crate::Error;

const SALT_SIZE: usize = 64;

type Salt = [u8; SALT_SIZE];

pub fn derive_key(okm: &mut [u8], ikm: &[u8], context: Option<&[u8]>) -> Result<(), Error> {
    let salt: Salt = [0; SALT_SIZE];
    hkdf_sha512(okm, ikm, Some(&salt), context).or(Err(Error::KeyDerivation))
}
