pub const DIGEST_SIZE: usize = 64;
pub const FINGERPRINT_SIZE: usize = 32;
pub const IKM_SIZE: usize = 32;
pub const INDEX_SIZE: usize = 4;
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
pub const SIZE_SIZE: usize = 8;
pub const STATE_SIZE: usize = 512;
pub const TAG_SIZE: usize = 16;

pub const HELLO_SIZE: usize = PUBLIC_KEY_SIZE * 2;
pub const KEY_PAIR_SIZE: usize = PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE;
pub const SAFETY_NUMBER_SIZE: usize = FINGERPRINT_SIZE * 2;
pub const TRANSCRIPT_SIZE: usize = PUBLIC_KEY_SIZE * 2;

pub const FINGERPRINT_ITERATIONS: u16 = 5200;
pub const FINGERPRINT_DIVISOR: u32 = 100000;

pub const INFO: [u8; 9] = [97, 117, 116, 111, 103, 114, 97, 112, 104];

pub const IDENTITY_KEY_PAIR_OFFSET: usize = 0;
pub const IDENTITY_PUBLIC_KEY_OFFSET: usize = IDENTITY_KEY_PAIR_OFFSET + PRIVATE_KEY_SIZE;
pub const THEIR_IDENTITY_KEY_OFFSET: usize = IDENTITY_KEY_PAIR_OFFSET + KEY_PAIR_SIZE;
pub const SENDING_NONCE_OFFSET: usize = THEIR_IDENTITY_KEY_OFFSET + PUBLIC_KEY_SIZE;
pub const SENDING_INDEX_OFFSET: usize = SENDING_NONCE_OFFSET + NONCE_SIZE - INDEX_SIZE;
pub const SENDING_KEY_OFFSET: usize = SENDING_INDEX_OFFSET + INDEX_SIZE;
pub const RECEIVING_NONCE_OFFSET: usize = SENDING_KEY_OFFSET + SECRET_KEY_SIZE;
pub const RECEIVING_INDEX_OFFSET: usize = RECEIVING_NONCE_OFFSET + NONCE_SIZE - INDEX_SIZE;
pub const RECEIVING_KEY_OFFSET: usize = RECEIVING_INDEX_OFFSET + INDEX_SIZE;
pub const SKIPPED_INDEXES_MIN_OFFSET: usize = RECEIVING_KEY_OFFSET + SECRET_KEY_SIZE;
pub const SKIPPED_INDEXES_MAX_OFFSET: usize = STATE_SIZE - INDEX_SIZE;
pub const EPHEMERAL_KEY_PAIR_OFFSET: usize = SKIPPED_INDEXES_MIN_OFFSET;
pub const EPHEMERAL_PUBLIC_KEY_OFFSET: usize = EPHEMERAL_KEY_PAIR_OFFSET + PRIVATE_KEY_SIZE;
pub const THEIR_EPHEMERAL_KEY_OFFSET: usize = EPHEMERAL_KEY_PAIR_OFFSET + KEY_PAIR_SIZE;
pub const TRANSCRIPT_OFFSET: usize = THEIR_EPHEMERAL_KEY_OFFSET + PUBLIC_KEY_SIZE;
