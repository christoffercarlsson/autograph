use autograph::{Autograph, AutographError, Bytes, KeyPair};

struct TestEnv {
    pub identity_key_pair: KeyPair,
    pub ephemeral_key_pair: KeyPair,
    pub handshake: Bytes,
}

fn create_alice_env() -> TestEnv {
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
    let handshake: Bytes = vec![
        238, 58, 38, 30, 141, 34, 200, 183, 28, 206, 215, 73, 200, 125, 92, 152, 101, 211, 214,
        130, 33, 158, 114, 200, 43, 30, 212, 100, 176, 149, 15, 111, 170, 186, 36, 10, 90, 136, 46,
        170, 120, 191, 170, 14, 31, 53, 72, 56, 227, 194, 21, 164, 251, 208, 203, 182, 242, 115, 6,
        54, 114, 120, 212, 226, 72, 160, 235, 116, 148, 31, 19, 62, 52, 116, 28, 172, 227, 191, 95,
        152, 15, 140, 105, 200, 21, 203, 72, 193, 215, 42, 20, 254, 193, 178, 56, 137,
    ];
    TestEnv {
        identity_key_pair,
        ephemeral_key_pair,
        handshake,
    }
}

fn create_bob_env() -> TestEnv {
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
    let handshake: Bytes = vec![
        40, 96, 87, 46, 204, 210, 12, 62, 80, 86, 55, 252, 191, 201, 183, 188, 150, 80, 124, 92,
        248, 44, 173, 8, 66, 54, 229, 117, 245, 117, 243, 248, 77, 227, 184, 224, 105, 115, 69,
        212, 103, 64, 198, 124, 122, 196, 195, 215, 250, 95, 169, 218, 185, 119, 150, 206, 130,
        255, 243, 124, 48, 52, 32, 211, 77, 244, 171, 54, 222, 115, 138, 209, 166, 140, 240, 181,
        115, 173, 224, 224, 108, 145, 15, 210, 138, 188, 76, 13, 29, 19, 188, 120, 188, 109, 89,
        34,
    ];
    TestEnv {
        identity_key_pair,
        ephemeral_key_pair,
        handshake,
    }
}

fn perform_key_exchange(
    is_initator: bool,
    our_env: TestEnv,
    their_env: TestEnv,
) -> Result<(Bytes, Bytes), AutographError> {
    let autograph = Autograph::new()?;
    let sign = autograph.create_sign(&our_env.identity_key_pair.private_key);
    let (handshake, _) = autograph.perform_key_exchange(
        &sign,
        &our_env.identity_key_pair.public_key,
        is_initator,
        our_env.ephemeral_key_pair,
        &their_env.identity_key_pair.public_key,
        their_env.ephemeral_key_pair.public_key,
    )?;
    Ok((handshake, our_env.handshake))
}

fn calculate_handshake(is_initator: bool) -> Result<(Bytes, Bytes), AutographError> {
    let a = create_alice_env();
    let b = create_bob_env();
    if is_initator {
        perform_key_exchange(true, a, b)
    } else {
        perform_key_exchange(false, b, a)
    }
}

#[test]
fn test_key_exchange() {
    let (alice_left, alice_right) = calculate_handshake(true).unwrap();
    let (bob_left, bob_right) = calculate_handshake(false).unwrap();
    assert_eq!(alice_left, alice_right);
    assert_eq!(bob_left, bob_right);
}
