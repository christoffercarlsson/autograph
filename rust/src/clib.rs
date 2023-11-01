extern "C" {
    pub fn autograph_init() -> i32;

    pub fn autograph_key_exchange(
        transcript: *mut u8,
        handshake: *mut u8,
        our_secret_key: *mut u8,
        their_secret_key: *mut u8,
        is_initiator: u32,
        our_private_identity_key: *const u8,
        our_public_identity_key: *const u8,
        our_private_ephemeral_key: *mut u8,
        our_public_ephemeral_key: *const u8,
        their_public_identity_key: *const u8,
        their_public_ephemeral_key: *const u8,
    ) -> i32;

    pub fn autograph_key_exchange_signature(
        handshake: *mut u8,
        our_secret_key: *mut u8,
        their_secret_key: *mut u8,
        is_initiator: u32,
        our_signature: *const u8,
        our_private_ephemeral_key: *mut u8,
        their_public_ephemeral_key: *const u8,
    ) -> i32;

    pub fn autograph_key_exchange_transcript(
        transcript: *mut u8,
        is_initiator: u32,
        our_identity_key: *const u8,
        our_ephemeral_key: *const u8,
        their_identity_key: *const u8,
        their_ephemeral_key: *const u8,
    ) -> i32;

    pub fn autograph_key_exchange_verify(
        transcript: *const u8,
        their_identity_key: *const u8,
        their_secret_key: *const u8,
        ciphertext: *const u8,
    ) -> i32;

    pub fn autograph_key_pair_ephemeral(private_key: *mut u8, public_key: *mut u8) -> i32;

    pub fn autograph_key_pair_identity(private_key: *mut u8, public_key: *mut u8) -> i32;

    pub fn autograph_read_uint32(bytes: *const u8) -> u32;

    pub fn autograph_read_uint64(bytes: *const u8) -> u64;

    pub fn autograph_safety_number(
        safety_number: *mut u8,
        our_identity_key: *const u8,
        their_identity_key: *const u8,
    ) -> i32;

    pub fn autograph_decrypt(
        plaintext: *mut u8,
        plaintext_size: *mut u8,
        message_index: *mut u8,
        decrypt_index: *mut u8,
        skipped_keys: *mut u8,
        key: *mut u8,
        message: *const u8,
        message_size: u32,
    ) -> i32;

    pub fn autograph_encrypt(
        message: *mut u8,
        index: *mut u8,
        key: *mut u8,
        plaintext: *const u8,
        plaintext_size: u32,
    ) -> i32;

    pub fn autograph_sign_data(
        signature: *mut u8,
        our_private_key: *const u8,
        their_public_key: *const u8,
        data: *const u8,
        data_size: u32,
    ) -> i32;

    pub fn autograph_sign_identity(
        signature: *mut u8,
        our_private_key: *const u8,
        their_public_key: *const u8,
    ) -> i32;

    pub fn autograph_subject(
        subject: *mut u8,
        their_public_key: *const u8,
        data: *const u8,
        data_size: u32,
    ) -> i32;

    pub fn autograph_verify_data(
        their_public_key: *const u8,
        certificates: *const u8,
        certificate_count: u32,
        data: *const u8,
        data_size: u32,
    ) -> i32;

    pub fn autograph_verify_identity(
        their_public_key: *const u8,
        certificates: *const u8,
        certificate_count: u32,
    ) -> i32;

    pub fn autograph_sign_subject(
        signature: *mut u8,
        private_key: *const u8,
        subject: *const u8,
        subject_size: u32,
    ) -> i32;

    pub fn autograph_ciphertext_size(plaintext_size: u32) -> u32;

    pub fn autograph_handshake_size() -> u32;

    pub fn autograph_index_size() -> u32;

    pub fn autograph_plaintext_size(ciphertext_size: u32) -> u32;

    pub fn autograph_private_key_size() -> u32;

    pub fn autograph_public_key_size() -> u32;

    pub fn autograph_safety_number_size() -> u32;

    pub fn autograph_secret_key_size() -> u32;

    pub fn autograph_signature_size() -> u32;

    pub fn autograph_size_size() -> u32;

    pub fn autograph_skipped_keys_size() -> u32;

    pub fn autograph_subject_size(size: u32) -> u32;

    pub fn autograph_transcript_size() -> u32;
}
