package constants

const DIGEST_SIZE uint16 = 64
const FINGERPRINT_SIZE uint16 = 32
const IKM_SIZE uint16 = 32
const INDEX_SIZE uint16 = 4
const NONCE_SIZE uint16 = 12
const OKM_SIZE uint16 = 64
const PADDING_BLOCK_SIZE uint16 = 16
const PADDING_BYTE uint8 = 128
const PRIVATE_KEY_SIZE uint16 = 32
const PUBLIC_KEY_SIZE uint16 = 32
const SALT_SIZE uint16 = 64
const SECRET_KEY_SIZE uint16 = 32
const SHARED_SECRET_SIZE uint16 = 32
const SIGNATURE_SIZE uint16 = 64
const SIZE_SIZE uint16 = 8
const STATE_SIZE uint16 = 512
const TAG_SIZE uint16 = 16

const HELLO_SIZE uint16 = PUBLIC_KEY_SIZE * 2
const KEY_PAIR_SIZE uint16 = PRIVATE_KEY_SIZE + PUBLIC_KEY_SIZE
const SAFETY_NUMBER_SIZE uint16 = FINGERPRINT_SIZE * 2
const TRANSCRIPT_SIZE uint16 = PUBLIC_KEY_SIZE * 2

const FINGERPRINT_ITERATIONS uint16 = 5200
const FINGERPRINT_DIVISOR uint32 = 100000

var INFO = []byte{97, 117, 116, 111, 103, 114, 97, 112, 104}

const IDENTITY_KEY_PAIR_OFFSET uint16 = 0
const IDENTITY_PUBLIC_KEY_OFFSET uint16 = IDENTITY_KEY_PAIR_OFFSET + PRIVATE_KEY_SIZE
const THEIR_IDENTITY_KEY_OFFSET uint16 = IDENTITY_KEY_PAIR_OFFSET + KEY_PAIR_SIZE
const SENDING_NONCE_OFFSET uint16 = THEIR_IDENTITY_KEY_OFFSET + PUBLIC_KEY_SIZE
const SENDING_INDEX_OFFSET uint16 = SENDING_NONCE_OFFSET + NONCE_SIZE - INDEX_SIZE
const SENDING_KEY_OFFSET uint16 = SENDING_INDEX_OFFSET + INDEX_SIZE
const RECEIVING_NONCE_OFFSET uint16 = SENDING_KEY_OFFSET + SECRET_KEY_SIZE
const RECEIVING_INDEX_OFFSET uint16 = RECEIVING_NONCE_OFFSET + NONCE_SIZE - INDEX_SIZE
const RECEIVING_KEY_OFFSET uint16 = RECEIVING_INDEX_OFFSET + INDEX_SIZE
const SKIPPED_INDEXES_MIN_OFFSET uint16 = RECEIVING_KEY_OFFSET + SECRET_KEY_SIZE
const SKIPPED_INDEXES_MAX_OFFSET uint16 = STATE_SIZE - INDEX_SIZE
const EPHEMERAL_KEY_PAIR_OFFSET uint16 = SKIPPED_INDEXES_MIN_OFFSET
const EPHEMERAL_PUBLIC_KEY_OFFSET uint16 = EPHEMERAL_KEY_PAIR_OFFSET + PRIVATE_KEY_SIZE
const THEIR_EPHEMERAL_KEY_OFFSET uint16 = EPHEMERAL_KEY_PAIR_OFFSET + KEY_PAIR_SIZE
const TRANSCRIPT_OFFSET uint16 = THEIR_EPHEMERAL_KEY_OFFSET + PUBLIC_KEY_SIZE
const DEFAULT_SKIPPED_INDEXES_COUNT uint16 = 100