use rand::rngs::OsRng;

use autograph_protocol::{generate_identity_key_pair, generate_session_key_pair};

const KEY_PAIR_SIZE: usize = 64;

#[test]
fn test_generate_session_key_pair() {
    let key_pair = generate_session_key_pair(OsRng).unwrap();
    assert_ne!(key_pair, vec![0; KEY_PAIR_SIZE]);
}

#[test]
fn test_generate_identity_key_pair() {
    let key_pair = generate_identity_key_pair(OsRng).unwrap();
    assert_ne!(key_pair, vec![0; KEY_PAIR_SIZE]);
}
