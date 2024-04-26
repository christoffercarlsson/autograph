pub const DIGEST_SIZE: usize = 64;
pub const FINGERPRINT_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const OKM_SIZE: usize = 64;
pub const PADDING_BLOCK_SIZE: usize = 16;
pub const PADDING_BYTE: u8 = 128;
pub const PRIVATE_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SALT_SIZE: usize = 64;
pub const SECRET_KEY_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const TAG_SIZE: usize = 16;

pub const KEY_PAIR_SIZE: usize = PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE;
pub const SAFETY_NUMBER_SIZE: usize = FINGERPRINT_SIZE * 2;
pub const TRANSCRIPT_SIZE: usize = PUBLIC_KEY_SIZE * 2;

pub const FINGERPRINT_ITERATIONS: u16 = 5200;
pub const FINGERPRINT_DIVISOR: u32 = 100000;

pub const INFO: [u8; 9] = [97, 117, 116, 111, 103, 114, 97, 112, 104];

pub const DEFAULT_SKIPPED_INDEXES_COUNT: u16 = 100;
