use autograph::Autograph;

#[test]
fn test_generate_ephemeral_key_pair() {
    let autograph = Autograph::new().unwrap();
    let result = autograph.generate_ephemeral_key_pair();
    assert!(result.success);
    assert_eq!(result.key_pair.private_key.len(), 32);
    assert_eq!(result.key_pair.public_key.len(), 32);
}

#[test]
fn test_generate_identity_key_pair() {
    let autograph = Autograph::new().unwrap();
    let result = autograph.generate_identity_key_pair();
    assert!(result.success);
    assert_eq!(result.key_pair.private_key.len(), 32);
    assert_eq!(result.key_pair.public_key.len(), 32);
}
