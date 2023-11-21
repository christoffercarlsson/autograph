use autograph::{generate_ephemeral_key_pair, generate_identity_key_pair};

#[test]
fn test_generate_ephemeral_key_pair() {
    let key_pair = generate_ephemeral_key_pair().unwrap();
    assert_eq!(key_pair.private_key.len(), 32);
    assert_eq!(key_pair.public_key.len(), 32);
}

#[test]
fn test_generate_identity_key_pair() {
    let key_pair = generate_identity_key_pair().unwrap();
    assert_eq!(key_pair.private_key.len(), 32);
    assert_eq!(key_pair.public_key.len(), 32);
}
