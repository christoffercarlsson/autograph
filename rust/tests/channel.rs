extern crate alloc;

use alloc::vec::Vec;

use autograph::{create_sign, Channel, KeyPair};

struct TestEnv {
    pub certificate_data: Vec<u8>,
    pub certificate_identity: Vec<u8>,
    pub data: Vec<u8>,
    pub ephemeral_key_pair: KeyPair,
    pub handshake: Vec<u8>,
    pub identity_key_pair: KeyPair,
    pub message: Vec<u8>,
    pub safety_number: Vec<u8>,
    pub signature_data: Vec<u8>,
    pub signature_identity: Vec<u8>,
}

impl TestEnv {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        certificate_data: Vec<u8>,
        certificate_identity: Vec<u8>,
        ephemeral_key_pair: KeyPair,
        identity_key_pair: KeyPair,
        handshake: Vec<u8>,
        message: Vec<u8>,
        signature_data: Vec<u8>,
        signature_identity: Vec<u8>,
    ) -> Self {
        Self {
            certificate_data,
            certificate_identity,
            data: vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100],
            ephemeral_key_pair,
            handshake,
            identity_key_pair,
            message,
            safety_number: vec![
                52, 52, 57, 52, 50, 50, 53, 55, 54, 50, 48, 53, 51, 51, 49, 55, 56, 54, 48, 50, 55,
                53, 56, 48, 54, 52, 56, 52, 53, 49, 53, 55, 50, 49, 50, 54, 49, 50, 50, 49, 57, 52,
                53, 57, 52, 50, 55, 54, 49, 49, 54, 49, 57, 50, 52, 53, 52, 57, 50, 54,
            ],
            signature_data,
            signature_identity,
        }
    }
}

fn create_alice_env() -> TestEnv {
    let certificate_data: Vec<u8> = vec![
        251, 196, 170, 200, 183, 119, 18, 130, 9, 255, 140, 77, 56, 104, 92, 11, 42, 224, 208, 28,
        110, 241, 103, 77, 34, 32, 164, 58, 255, 108, 255, 222, 20, 76, 211, 173, 168, 254, 145,
        154, 196, 46, 118, 241, 200, 158, 125, 189, 120, 214, 213, 161, 217, 229, 164, 90, 10, 128,
        115, 116, 69, 30, 153, 219, 68, 143, 64, 1, 161, 239, 230, 6, 82, 13, 100, 27, 126, 169,
        42, 49, 85, 79, 232, 15, 30, 22, 109, 118, 6, 196, 207, 18, 60, 63, 25, 1,
    ];
    let certificate_identity: Vec<u8> = vec![
        126, 118, 172, 19, 4, 38, 118, 77, 202, 146, 28, 11, 166, 253, 115, 109, 204, 196, 31, 146,
        128, 17, 242, 19, 95, 146, 105, 135, 38, 36, 178, 138, 141, 196, 191, 87, 226, 187, 57, 49,
        19, 119, 116, 5, 5, 247, 5, 171, 137, 143, 52, 144, 19, 146, 38, 120, 124, 247, 154, 251,
        30, 247, 63, 28, 229, 241, 8, 34, 86, 159, 15, 87, 120, 95, 0, 58, 188, 176, 71, 18, 254,
        57, 98, 211, 129, 168, 241, 51, 236, 181, 12, 63, 185, 130, 176, 2,
    ];
    let ephemeral_key_pair = KeyPair {
        private_key: vec![
            171, 243, 152, 144, 76, 145, 84, 13, 243, 173, 102, 244, 84, 223, 43, 104, 182, 128,
            230, 247, 121, 221, 222, 203, 10, 80, 43, 88, 177, 155, 1, 114,
        ],
        public_key: vec![
            16, 9, 47, 109, 23, 19, 165, 137, 95, 186, 203, 186, 154, 179, 116, 3, 160, 119, 225,
            180, 226, 19, 172, 45, 113, 125, 124, 86, 94, 159, 161, 119,
        ],
    };
    let identity_key_pair = KeyPair {
        private_key: vec![
            43, 6, 246, 172, 137, 170, 33, 12, 118, 177, 111, 60, 19, 37, 65, 122, 28, 34, 200,
            251, 96, 35, 187, 52, 74, 224, 143, 39, 90, 51, 33, 140,
        ],
        public_key: vec![
            91, 119, 85, 151, 32, 20, 121, 20, 19, 106, 90, 56, 141, 90, 16, 210, 14, 244, 60, 251,
            140, 48, 190, 65, 194, 35, 166, 246, 1, 209, 4, 33,
        ],
    };
    let handshake: Vec<u8> = vec![
        238, 58, 38, 30, 141, 34, 200, 183, 28, 206, 215, 73, 200, 125, 92, 152, 101, 211, 214,
        130, 33, 158, 114, 200, 43, 30, 212, 100, 176, 149, 15, 111, 170, 186, 36, 10, 90, 136, 46,
        170, 120, 191, 170, 14, 31, 53, 72, 56, 227, 194, 21, 164, 251, 208, 203, 182, 242, 115, 6,
        54, 114, 120, 212, 226, 72, 160, 235, 116, 148, 31, 19, 62, 52, 116, 28, 172, 227, 191, 95,
        152, 15, 140, 105, 200, 21, 203, 72, 193, 215, 42, 20, 254, 193, 178, 56, 137,
    ];
    let message: Vec<u8> = vec![
        133, 247, 214, 87, 210, 66, 77, 105, 105, 94, 229, 248, 76, 207, 31, 228, 73, 37, 32, 45,
        125, 163, 240, 75, 45, 197, 224, 166, 218, 59, 107, 249,
    ];
    let signature_data: Vec<u8> = vec![
        86, 231, 106, 104, 140, 212, 209, 113, 91, 48, 249, 242, 132, 150, 129, 18, 62, 67, 44,
        187, 71, 9, 28, 5, 164, 244, 165, 222, 124, 11, 197, 55, 123, 174, 9, 14, 186, 118, 86,
        242, 240, 170, 239, 176, 78, 255, 85, 28, 88, 148, 202, 108, 151, 160, 93, 1, 128, 129,
        255, 123, 238, 191, 29, 1,
    ];
    let signature_identity: Vec<u8> = vec![
        183, 19, 9, 47, 241, 207, 111, 69, 199, 68, 135, 48, 131, 140, 112, 168, 61, 244, 34, 107,
        219, 194, 177, 99, 178, 109, 218, 237, 118, 1, 13, 205, 231, 138, 74, 246, 88, 149, 36, 65,
        219, 62, 154, 70, 185, 35, 251, 98, 186, 16, 56, 79, 18, 144, 193, 183, 27, 2, 11, 71, 83,
        20, 168, 7,
    ];
    TestEnv::new(
        certificate_data,
        certificate_identity,
        ephemeral_key_pair,
        identity_key_pair,
        handshake,
        message,
        signature_data,
        signature_identity,
    )
}

fn create_bob_env() -> TestEnv {
    let certificate_data: Vec<u8> = vec![
        123, 223, 90, 28, 163, 65, 187, 199, 14, 78, 92, 116, 38, 48, 178, 123, 72, 213, 94, 252,
        250, 127, 184, 0, 187, 249, 157, 102, 227, 241, 114, 20, 82, 239, 167, 88, 84, 82, 16, 198,
        184, 193, 35, 9, 78, 135, 162, 198, 47, 53, 179, 3, 242, 165, 38, 18, 209, 74, 113, 86, 99,
        124, 196, 124, 75, 99, 159, 106, 233, 232, 188, 251, 194, 157, 166, 7, 134, 203, 32, 253,
        65, 90, 40, 91, 76, 25, 252, 156, 139, 154, 148, 183, 71, 7, 109, 5,
    ];
    let certificate_identity: Vec<u8> = vec![
        97, 114, 246, 28, 48, 150, 138, 154, 28, 234, 226, 183, 186, 225, 166, 166, 43, 109, 145,
        194, 105, 51, 155, 138, 48, 180, 100, 51, 113, 57, 150, 211, 94, 131, 142, 67, 234, 107,
        103, 51, 205, 132, 182, 252, 157, 59, 44, 23, 12, 141, 221, 157, 239, 30, 80, 111, 164, 85,
        21, 221, 217, 98, 151, 57, 213, 250, 195, 119, 178, 45, 107, 31, 26, 153, 30, 132, 207,
        177, 67, 160, 231, 198, 207, 32, 134, 210, 55, 9, 188, 20, 186, 130, 156, 122, 77, 4,
    ];
    let ephemeral_key_pair = KeyPair {
        private_key: vec![
            252, 67, 175, 250, 230, 100, 145, 82, 139, 125, 242, 5, 40, 8, 155, 104, 37, 224, 5,
            96, 105, 46, 42, 202, 158, 63, 177, 43, 112, 184, 207, 85,
        ],
        public_key: vec![
            249, 212, 82, 190, 253, 45, 230, 86, 74, 150, 239, 0, 26, 41, 131, 245, 177, 87, 106,
            105, 167, 58, 158, 184, 244, 65, 205, 42, 40, 80, 134, 52,
        ],
    };
    let identity_key_pair = KeyPair {
        private_key: vec![
            243, 11, 156, 139, 99, 129, 212, 8, 60, 53, 111, 123, 69, 158, 83, 255, 187, 192, 29,
            114, 69, 126, 243, 111, 122, 143, 170, 247, 140, 129, 60, 0,
        ],
        public_key: vec![
            232, 130, 200, 162, 218, 101, 75, 210, 196, 152, 235, 97, 118, 3, 241, 131, 200, 140,
            54, 155, 28, 46, 158, 76, 96, 4, 150, 61, 34, 13, 133, 138,
        ],
    };
    let handshake: Vec<u8> = vec![
        40, 96, 87, 46, 204, 210, 12, 62, 80, 86, 55, 252, 191, 201, 183, 188, 150, 80, 124, 92,
        248, 44, 173, 8, 66, 54, 229, 117, 245, 117, 243, 248, 77, 227, 184, 224, 105, 115, 69,
        212, 103, 64, 198, 124, 122, 196, 195, 215, 250, 95, 169, 218, 185, 119, 150, 206, 130,
        255, 243, 124, 48, 52, 32, 211, 77, 244, 171, 54, 222, 115, 138, 209, 166, 140, 240, 181,
        115, 173, 224, 224, 108, 145, 15, 210, 138, 188, 76, 13, 29, 19, 188, 120, 188, 109, 89,
        34,
    ];
    let message: Vec<u8> = vec![
        215, 195, 161, 229, 121, 212, 73, 131, 33, 122, 165, 228, 150, 205, 107, 127, 120, 84, 39,
        99, 138, 32, 20, 143, 68, 34, 45, 215, 62, 214, 84, 181,
    ];
    let signature_data: Vec<u8> = vec![
        188, 36, 195, 130, 177, 84, 21, 74, 125, 139, 109, 135, 207, 42, 213, 11, 153, 158, 183,
        160, 112, 141, 216, 204, 167, 194, 159, 123, 221, 162, 50, 220, 49, 54, 123, 73, 132, 73,
        15, 144, 65, 252, 249, 192, 145, 159, 22, 224, 143, 25, 226, 32, 54, 44, 139, 196, 85, 254,
        198, 61, 138, 244, 223, 4,
    ];
    let signature_identity: Vec<u8> = vec![
        173, 114, 114, 160, 51, 91, 40, 39, 223, 144, 168, 53, 94, 199, 250, 184, 88, 132, 31, 232,
        50, 177, 147, 144, 102, 146, 120, 27, 57, 63, 60, 151, 237, 224, 85, 65, 200, 38, 227, 34,
        88, 131, 168, 236, 107, 4, 200, 54, 232, 176, 16, 44, 144, 106, 77, 28, 246, 104, 17, 77,
        150, 92, 116, 0,
    ];
    TestEnv::new(
        certificate_data,
        certificate_identity,
        ephemeral_key_pair,
        identity_key_pair,
        handshake,
        message,
        signature_data,
        signature_identity,
    )
}

#[test]
fn test_channel() {
    let alice_env = create_alice_env();
    let bob_env = create_bob_env();
    let alice_sign = create_sign(alice_env.identity_key_pair.private_key.clone());
    let bob_sign = create_sign(bob_env.identity_key_pair.private_key.clone());
    let mut a = Channel::new(alice_sign, alice_env.identity_key_pair.public_key.clone()).unwrap();
    let mut b = Channel::new(bob_sign, bob_env.identity_key_pair.public_key.clone()).unwrap();
    test_key_exchange(&mut a, &mut b, &alice_env, &bob_env);
    test_safety_number(&mut a, &mut b, &alice_env);
    test_alice_message_to_bob(&mut a, &mut b, &alice_env);
    test_bob_message_to_alice(&mut a, &mut b, &bob_env);
    test_bob_certify_alice_data(&mut b, &bob_env);
    test_alice_certify_bob_data(&mut a, &alice_env);
    test_bob_certify_alice_identity(&mut b, &bob_env);
    test_alice_certify_bob_identity(&mut a, &alice_env);
    test_bob_verify_alice_data(&mut b, &bob_env);
    test_alice_verify_bob_data(&mut a, &alice_env);
    test_bob_verify_alice_identity(&mut b, &bob_env);
    test_alice_verify_bob_identity(&mut a, &alice_env);
    test_out_of_order_messages(&mut a, &mut b);
}

// Should allow Alice and Bob to perform a key exchange
fn test_key_exchange(a: &mut Channel, b: &mut Channel, alice_env: &TestEnv, bob_env: &TestEnv) {
    let alice_handshake = a
        .perform_key_exchange(
            true,
            alice_env.ephemeral_key_pair.clone(),
            bob_env.identity_key_pair.public_key.clone(),
            bob_env.ephemeral_key_pair.public_key.clone(),
        )
        .unwrap();
    let bob_handshake = b
        .perform_key_exchange(
            false,
            bob_env.ephemeral_key_pair.clone(),
            alice_env.identity_key_pair.public_key.clone(),
            alice_env.ephemeral_key_pair.public_key.clone(),
        )
        .unwrap();
    assert_eq!(alice_handshake, alice_env.handshake);
    assert_eq!(bob_handshake, bob_env.handshake);
    a.verify_key_exchange(bob_handshake).unwrap();
    b.verify_key_exchange(alice_handshake).unwrap();
}

// Should allow Alice and Bob to calculate their safety numbers correctly
fn test_safety_number(a: &mut Channel, b: &mut Channel, env: &TestEnv) {
    let alice_safety_number = a.calculate_safety_number().unwrap();
    let bob_safety_number = b.calculate_safety_number().unwrap();
    assert_eq!(alice_safety_number, env.safety_number);
    assert_eq!(bob_safety_number, env.safety_number);
}

// Should allow Alice to send encrypted data to Bob
fn test_alice_message_to_bob(a: &mut Channel, b: &mut Channel, env: &TestEnv) {
    let (_, message) = a.encrypt(&env.data).unwrap();
    let (_, data) = b.decrypt(message.clone()).unwrap();
    assert_eq!(message, env.message);
    assert_eq!(data, env.data);
}

// Should allow Bob to send encrypted data to Alice
fn test_bob_message_to_alice(a: &mut Channel, b: &mut Channel, env: &TestEnv) {
    let (_, message) = b.encrypt(&env.data).unwrap();
    let (_, data) = a.decrypt(message.clone()).unwrap();
    assert_eq!(message, env.message);
    assert_eq!(data, env.data);
}

// Should allow Bob to certify Alice's ownership of her identity key and data
fn test_bob_certify_alice_data(b: &mut Channel, env: &TestEnv) {
    let signature = b.sign_data(&env.data).unwrap();
    assert_eq!(signature, env.signature_data);
}

// Should allow Alice to certify Bob's ownership of his identity key and data
fn test_alice_certify_bob_data(a: &mut Channel, env: &TestEnv) {
    let signature = a.sign_data(&env.data).unwrap();
    assert_eq!(signature, env.signature_data);
}

// Should allow Bob to certify Alice's ownership of her identity key
fn test_bob_certify_alice_identity(b: &mut Channel, env: &TestEnv) {
    let signature = b.sign_identity().unwrap();
    assert_eq!(signature, env.signature_identity);
}

// Should allow Alice to certify Bob's ownership of his identity key
fn test_alice_certify_bob_identity(a: &mut Channel, env: &TestEnv) {
    let signature = a.sign_identity().unwrap();
    assert_eq!(signature, env.signature_identity);
}

// Should allow Bob to verify Alice's ownership of her identity key and data
// based on Charlie's public key and signature
fn test_bob_verify_alice_data(b: &mut Channel, env: &TestEnv) {
    let verified = b.verify_data(&env.certificate_data, &env.data).unwrap();
    assert!(verified);
}

// Should allow Alice to verify Bob's ownership of his identity key and ddata
// based on Charlie's public key and signature
fn test_alice_verify_bob_data(a: &mut Channel, env: &TestEnv) {
    let verified = a.verify_data(&env.certificate_data, &env.data).unwrap();
    assert!(verified);
}

// Should allow Bob to verify Alice's ownership of her identity key based on
// Charlie's public key and signature
fn test_bob_verify_alice_identity(b: &mut Channel, env: &TestEnv) {
    let verified = b.verify_identity(&env.certificate_identity).unwrap();
    assert!(verified);
}

// Should allow Alice to verify Bob's ownership of his identity key based on
// Charlie's public key and signature
fn test_alice_verify_bob_identity(a: &mut Channel, env: &TestEnv) {
    let verified = a.verify_identity(&env.certificate_identity).unwrap();
    assert!(verified);
}

// Should handle out of order messages correctly
fn test_out_of_order_messages(a: &mut Channel, b: &mut Channel) {
    let d1: Vec<u8> = vec![1, 2, 3];
    let d2: Vec<u8> = vec![4, 5, 6];
    let d3: Vec<u8> = vec![7, 8, 9];
    let d4: Vec<u8> = vec![10, 11, 12];
    let (_, m1) = a.encrypt(&d1).unwrap();
    let (_, m2) = a.encrypt(&d2).unwrap();
    let (_, m3) = a.encrypt(&d3).unwrap();
    let (_, m4) = a.encrypt(&d4).unwrap();
    let (i4, p4) = b.decrypt(m4).unwrap();
    let (i2, p2) = b.decrypt(m2).unwrap();
    let (i3, p3) = b.decrypt(m3).unwrap();
    let (i1, p1) = b.decrypt(m1).unwrap();
    // Index start at 2 since another test (test_alice_message_to_bob) that
    // uses the same channel ran before this test
    assert_eq!(i1, 2);
    assert_eq!(i2, 3);
    assert_eq!(i3, 4);
    assert_eq!(i4, 5);
    assert_eq!(p1, d1);
    assert_eq!(p2, d2);
    assert_eq!(p3, d3);
    assert_eq!(p4, d4);
}
