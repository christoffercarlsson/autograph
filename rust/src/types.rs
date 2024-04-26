use crate::constants::{
    DIGEST_SIZE, FINGERPRINT_SIZE, KEY_PAIR_SIZE, NONCE_SIZE, OKM_SIZE, PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE, SAFETY_NUMBER_SIZE, SECRET_KEY_SIZE, SHARED_SECRET_SIZE, SIGNATURE_SIZE,
    TRANSCRIPT_SIZE,
};

pub type Digest = [u8; DIGEST_SIZE];
pub type Fingerprint = [u8; FINGERPRINT_SIZE];
pub type KeyPair = [u8; KEY_PAIR_SIZE];
pub type Nonce = [u8; NONCE_SIZE];
pub type Okm = [u8; OKM_SIZE];
pub type PrivateKey = [u8; PRIVATE_KEY_SIZE];
pub type PublicKey = [u8; PUBLIC_KEY_SIZE];
pub type SafetyNumber = [u8; SAFETY_NUMBER_SIZE];
pub type SecretKey = [u8; SECRET_KEY_SIZE];
pub type SharedSecret = [u8; SHARED_SECRET_SIZE];
pub type Signature = [u8; SIGNATURE_SIZE];
pub type Transcript = [u8; TRANSCRIPT_SIZE];
