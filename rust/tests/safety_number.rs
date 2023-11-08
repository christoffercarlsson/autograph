use autograph::{Autograph, Bytes, KeyPair};

#[test]
fn test_calculate_safety_number() {
    let alice_identity_key_pair = KeyPair {
        private_key: vec![
            43, 6, 246, 172, 137, 170, 33, 12, 118, 177, 111, 60, 19, 37, 65, 122, 28, 34, 200,
            251, 96, 35, 187, 52, 74, 224, 143, 39, 90, 51, 33, 140,
        ],
        public_key: vec![
            91, 119, 85, 151, 32, 20, 121, 20, 19, 106, 90, 56, 141, 90, 16, 210, 14, 244, 60, 251,
            140, 48, 190, 65, 194, 35, 166, 246, 1, 209, 4, 33,
        ],
    };
    let bob_identity_key_pair = KeyPair {
        private_key: vec![
            243, 11, 156, 139, 99, 129, 212, 8, 60, 53, 111, 123, 69, 158, 83, 255, 187, 192, 29,
            114, 69, 126, 243, 111, 122, 143, 170, 247, 140, 129, 60, 0,
        ],
        public_key: vec![
            232, 130, 200, 162, 218, 101, 75, 210, 196, 152, 235, 97, 118, 3, 241, 131, 200, 140,
            54, 155, 28, 46, 158, 76, 96, 4, 150, 61, 34, 13, 133, 138,
        ],
    };
    let safety_number: Bytes = vec![
        52, 52, 57, 52, 50, 50, 53, 55, 54, 50, 48, 53, 51, 51, 49, 55, 56, 54, 48, 50, 55, 53, 56,
        48, 54, 52, 56, 52, 53, 49, 53, 55, 50, 49, 50, 54, 49, 50, 50, 49, 57, 52, 53, 57, 52, 50,
        55, 54, 49, 49, 54, 49, 57, 50, 52, 53, 52, 57, 50, 54,
    ];
    let autograph = Autograph::new().unwrap();
    let alice_sign = autograph.create_sign(&alice_identity_key_pair.private_key);
    let bob_sign = autograph.create_sign(&bob_identity_key_pair.private_key);
    let alice = autograph.create_initiator(&alice_sign, &alice_identity_key_pair.public_key);
    let bob = autograph.create_responder(&bob_sign, &bob_identity_key_pair.public_key);
    let a = (alice.calculate_safety_number)(&bob_identity_key_pair.public_key);
    let b = (bob.calculate_safety_number)(&alice_identity_key_pair.public_key);
    assert!(a.success);
    assert!(b.success);
    assert_eq!(a.safety_number, safety_number);
    assert_eq!(b.safety_number, safety_number);
}
