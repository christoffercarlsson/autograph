use autograph_protocol::{
    Channel, Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, SafetyNumber, X25519KeyPair,
};

#[test]
fn test_channel() {
    let alice_handshake: Ed25519Signature = [
        62, 101, 52, 138, 111, 7, 218, 11, 80, 228, 234, 143, 93, 143, 40, 78, 192, 67, 161, 165,
        120, 223, 71, 90, 227, 47, 92, 157, 192, 55, 193, 162, 156, 223, 162, 246, 190, 86, 82, 50,
        245, 72, 87, 252, 70, 19, 105, 153, 130, 140, 132, 118, 217, 37, 23, 242, 125, 12, 241,
        155, 181, 186, 71, 3,
    ];

    let bob_handshake: Ed25519Signature = [
        22, 51, 47, 208, 198, 143, 141, 242, 199, 185, 82, 142, 190, 105, 55, 152, 145, 185, 67,
        35, 122, 253, 201, 23, 74, 40, 110, 217, 60, 198, 123, 216, 195, 74, 74, 185, 65, 215, 2,
        151, 214, 117, 91, 122, 16, 145, 253, 88, 26, 50, 135, 226, 45, 126, 125, 22, 88, 214, 178,
        147, 69, 72, 143, 3,
    ];

    let alice_message = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 163, 119, 190, 202, 145, 128, 127, 100, 87, 76, 232, 9,
        201, 209, 122, 168, 129, 144, 60, 76, 154, 76, 234, 94, 30, 212, 216, 247, 65, 206, 157,
        166,
    ];

    let bob_message = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 174, 19, 249, 137, 111, 236, 219, 4, 106, 235, 3,
        139, 73, 51, 235, 18, 143, 182, 38, 136, 202, 26, 46, 3, 243, 247, 180, 29, 156, 92, 206,
    ];

    let alice_signature_bob_data: Ed25519Signature = [
        198, 235, 143, 145, 121, 29, 143, 128, 167, 118, 33, 71, 38, 209, 169, 2, 134, 90, 203, 72,
        171, 252, 236, 237, 55, 41, 227, 248, 198, 165, 58, 185, 31, 70, 147, 96, 181, 33, 188, 7,
        146, 43, 24, 197, 158, 216, 215, 49, 126, 186, 88, 238, 233, 86, 167, 207, 20, 150, 227,
        38, 160, 68, 82, 8,
    ];

    let alice_signature_bob_identity: Ed25519Signature = [
        170, 64, 159, 119, 20, 17, 130, 46, 124, 70, 154, 47, 90, 7, 116, 204, 255, 198, 56, 60,
        24, 112, 214, 188, 212, 64, 210, 117, 228, 145, 111, 250, 84, 20, 216, 222, 21, 82, 213,
        225, 31, 28, 152, 211, 16, 82, 131, 7, 248, 186, 255, 184, 35, 205, 183, 167, 138, 179,
        217, 135, 163, 124, 13, 5,
    ];

    let bob_signature_alice_data: Ed25519Signature = [
        17, 229, 247, 220, 138, 161, 5, 224, 147, 178, 230, 168, 132, 164, 94, 3, 119, 118, 16,
        163, 222, 85, 3, 160, 88, 222, 210, 140, 222, 158, 254, 231, 182, 232, 78, 211, 150, 146,
        127, 164, 238, 221, 119, 12, 230, 54, 49, 103, 177, 72, 126, 225, 214, 41, 80, 214, 247,
        95, 23, 145, 227, 87, 172, 4,
    ];

    let bob_signature_alice_identity: Ed25519Signature = [
        186, 27, 195, 159, 150, 127, 96, 11, 25, 224, 30, 145, 56, 194, 138, 164, 70, 54, 243, 213,
        229, 203, 179, 218, 207, 213, 168, 160, 56, 32, 164, 245, 49, 102, 200, 36, 172, 152, 113,
        5, 82, 196, 154, 90, 20, 27, 180, 61, 189, 171, 20, 194, 165, 165, 65, 178, 190, 16, 44,
        82, 157, 68, 102, 13,
    ];

    let charlie_identity_key: Ed25519PublicKey = [
        129, 128, 10, 70, 174, 223, 175, 90, 43, 37, 148, 125, 188, 163, 110, 136, 15, 246, 192,
        76, 167, 8, 26, 149, 219, 223, 83, 47, 193, 159, 6, 3,
    ];

    let charlie_signature_alice_data: Ed25519Signature = [
        231, 126, 138, 39, 145, 83, 130, 243, 2, 56, 53, 185, 199, 242, 217, 239, 118, 208, 172, 6,
        201, 132, 94, 179, 57, 59, 160, 23, 150, 221, 67, 122, 176, 56, 160, 63, 7, 161, 169, 101,
        240, 97, 108, 137, 142, 99, 197, 44, 179, 142, 37, 4, 135, 162, 118, 160, 119, 245, 234,
        39, 26, 75, 71, 6,
    ];

    let charlie_signature_alice_identity: Ed25519Signature = [
        146, 120, 170, 85, 78, 187, 162, 243, 234, 149, 138, 201, 18, 132, 187, 129, 45, 53, 116,
        227, 178, 209, 200, 224, 149, 91, 166, 120, 203, 73, 138, 189, 63, 231, 213, 177, 163, 114,
        66, 151, 61, 253, 109, 250, 226, 140, 249, 3, 188, 44, 127, 108, 196, 131, 204, 216, 54,
        239, 157, 49, 107, 202, 123, 9,
    ];

    let charlie_signature_bob_data: Ed25519Signature = [
        135, 249, 64, 214, 240, 146, 173, 141, 97, 18, 16, 47, 83, 125, 13, 166, 169, 96, 99, 21,
        215, 217, 236, 173, 120, 50, 143, 251, 228, 76, 195, 8, 248, 133, 170, 103, 122, 169, 190,
        57, 51, 14, 171, 199, 229, 55, 55, 195, 53, 202, 139, 118, 93, 68, 131, 96, 175, 50, 31,
        243, 170, 34, 102, 1,
    ];

    let charlie_signature_bob_identity: Ed25519Signature = [
        198, 41, 56, 189, 24, 9, 75, 102, 228, 51, 193, 102, 25, 51, 92, 1, 192, 219, 16, 17, 22,
        28, 22, 16, 198, 67, 248, 16, 98, 164, 99, 243, 254, 45, 69, 156, 50, 115, 205, 43, 155,
        242, 78, 64, 205, 218, 80, 171, 34, 128, 255, 51, 237, 60, 37, 224, 232, 149, 153, 213,
        204, 93, 26, 7,
    ];

    let data = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

    let safety_number: SafetyNumber = [
        0, 1, 33, 28, 0, 0, 133, 8, 0, 0, 122, 169, 0, 1, 95, 147, 0, 1, 10, 56, 0, 0, 92, 202, 0,
        1, 129, 249, 0, 0, 37, 3, 0, 0, 89, 52, 0, 0, 133, 56, 0, 0, 255, 89, 0, 0, 129, 161, 0, 1,
        132, 70, 0, 0, 169, 215, 0, 0, 29, 42, 0, 0, 153, 44,
    ];

    let alice_identity_key_pair: Ed25519KeyPair = [
        118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2, 56, 252, 122, 177,
        18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17, 213, 153, 88, 124, 93, 136, 104,
        111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243,
        24, 225, 91, 220, 141, 150,
    ];

    let bob_identity_key_pair: Ed25519KeyPair = [
        52, 0, 150, 226, 138, 192, 249, 231, 126, 199, 95, 240, 106, 17, 150, 95, 221, 247, 33,
        201, 19, 62, 4, 135, 169, 104, 128, 218, 250, 251, 243, 190, 177, 67, 45, 125, 158, 190,
        181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61, 200, 62, 29, 37, 150, 228, 137,
        114, 143, 77, 115, 135, 143, 103,
    ];

    let alice_session_key_pair: X25519KeyPair = [
        201, 142, 54, 248, 151, 150, 224, 79, 30, 126, 207, 157, 118, 85, 9, 212, 148, 156, 73,
        176, 107, 107, 47, 111, 95, 98, 33, 192, 80, 223, 48, 221, 35, 16, 23, 37, 205, 131, 166,
        97, 13, 81, 136, 246, 193, 253, 139, 193, 230, 155, 222, 221, 37, 114, 190, 87, 104, 44,
        210, 144, 127, 176, 198, 45,
    ];

    let bob_session_key_pair: X25519KeyPair = [
        74, 233, 106, 152, 76, 212, 181, 144, 132, 237, 223, 58, 122, 173, 99, 100, 152, 219, 214,
        210, 213, 72, 171, 73, 167, 92, 199, 196, 176, 66, 213, 208, 88, 115, 171, 4, 34, 181, 120,
        21, 10, 39, 204, 215, 158, 210, 177, 243, 28, 138, 52, 91, 236, 55, 30, 117, 10, 125, 87,
        232, 80, 6, 232, 93,
    ];

    let mut a = Channel::new();
    let mut b = Channel::new();

    let (alice_identity_key, alice_session_key) = a
        .set_key_pairs(&alice_identity_key_pair, &alice_session_key_pair)
        .unwrap();

    let (bob_identity_key, bob_session_key) = b
        .set_key_pairs(&bob_identity_key_pair, &bob_session_key_pair)
        .unwrap();

    a.set_public_keys(&bob_identity_key, &bob_session_key)
        .unwrap();
    b.set_public_keys(&alice_identity_key, &alice_session_key)
        .unwrap();

    test_key_exchange(&mut a, &mut b, alice_handshake, bob_handshake);
    test_authenticate(&a, &b, safety_number);
    test_alice_message_to_bob(&mut a, &mut b, &data, alice_message);
    test_bob_message_to_alice(&mut a, &mut b, &data, bob_message);
    test_bob_certify_alice_data(&b, &data, bob_signature_alice_data);
    test_alice_certify_bob_data(&a, &data, alice_signature_bob_data);
    test_bob_certify_alice_identity(&b, bob_signature_alice_identity);
    test_alice_certify_bob_identity(&a, alice_signature_bob_identity);
    test_bob_verify_alice_data(
        &b,
        &data,
        charlie_identity_key,
        charlie_signature_alice_data,
    );
    test_alice_verify_bob_data(&a, &data, charlie_identity_key, charlie_signature_bob_data);
    test_bob_verify_alice_identity(&b, charlie_identity_key, charlie_signature_alice_identity);
    test_alice_verify_bob_identity(&a, charlie_identity_key, charlie_signature_bob_identity);
    test_out_of_order_messages(&mut a, &mut b);
}

// Should allow Alice and Bob to perform a key exchange
fn test_key_exchange(
    a: &mut Channel,
    b: &mut Channel,
    alice_handshake: Ed25519Signature,
    bob_handshake: Ed25519Signature,
) {
    let handshake_alice = a.key_exchange().unwrap();
    let handshake_bob = b.key_exchange().unwrap();
    a.verify_key_exchange(&handshake_bob).unwrap();
    b.verify_key_exchange(&handshake_alice).unwrap();
    assert_eq!(handshake_alice, alice_handshake);
    assert_eq!(handshake_bob, bob_handshake);
}

// Should calculate safety numbers correctly
fn test_authenticate(a: &Channel, b: &Channel, safety_number: SafetyNumber) {
    let alice_id = "alice".as_bytes();
    let bob_id = "bob".as_bytes();
    let alice_safety_number = a.authenticate(alice_id, bob_id).unwrap();
    let bob_safety_number = b.authenticate(bob_id, alice_id).unwrap();
    assert_eq!(alice_safety_number, safety_number);
    assert_eq!(bob_safety_number, safety_number);
}

// Should allow Alice to send encrypted data to Bob
fn test_alice_message_to_bob(
    a: &mut Channel,
    b: &mut Channel,
    data: &[u8],
    alice_message: Vec<u8>,
) {
    let (encrypt_index, message) = a.encrypt(data).unwrap();
    let (decrypt_index, plaintext) = b.decrypt(&message).unwrap();
    assert_eq!(encrypt_index, 1);
    assert_eq!(decrypt_index, 1);
    assert_eq!(plaintext, data);
    assert_eq!(message, alice_message);
}

// Should allow Bob to send encrypted data to Alice
fn test_bob_message_to_alice(a: &mut Channel, b: &mut Channel, data: &[u8], bob_message: Vec<u8>) {
    let (_, message) = b.encrypt(data).unwrap();
    let (_, plaintext) = a.decrypt(&message).unwrap();
    assert_eq!(plaintext, data);
    assert_eq!(message, bob_message);
}

// Should allow Bob to certify Alice's ownership of her identity key and data
fn test_bob_certify_alice_data(
    b: &Channel,
    data: &[u8],
    bob_signature_alice_data: Ed25519Signature,
) {
    let signature = b.certify(Some(data)).unwrap();
    assert_eq!(signature, bob_signature_alice_data);
}

// Should allow Alice to certify Bob's ownership of his identity key and data
fn test_alice_certify_bob_data(
    a: &Channel,
    data: &[u8],
    alice_signature_bob_data: Ed25519Signature,
) {
    let signature = a.certify(Some(data)).unwrap();
    assert_eq!(signature, alice_signature_bob_data);
}

// Should allow Bob to certify Alice's ownership of her identity key
fn test_bob_certify_alice_identity(b: &Channel, bob_signature_alice_identity: Ed25519Signature) {
    let signature = b.certify(None).unwrap();
    assert_eq!(signature, bob_signature_alice_identity);
}

// Should allow Alice to certify Bob's ownership of his identity key
fn test_alice_certify_bob_identity(a: &Channel, alice_signature_bob_identity: Ed25519Signature) {
    let signature = a.certify(None).unwrap();
    assert_eq!(signature, alice_signature_bob_identity);
}

// Should allow Bob to verify Alice's ownership of her identity key and data
// based on Charlie's public key and signature
fn test_bob_verify_alice_data(
    b: &Channel,
    data: &[u8],
    charlie_identity_key: Ed25519PublicKey,
    charlie_signature_alice_data: Ed25519Signature,
) {
    b.verify(
        &charlie_identity_key,
        &charlie_signature_alice_data,
        Some(data),
    )
    .unwrap();
}

// Should allow Alice to verify Bob's ownership of his identity key and ddata
// based on Charlie's public key and signature
fn test_alice_verify_bob_data(
    a: &Channel,
    data: &[u8],
    charlie_identity_key: Ed25519PublicKey,
    charlie_signature_bob_data: Ed25519Signature,
) {
    a.verify(
        &charlie_identity_key,
        &charlie_signature_bob_data,
        Some(data),
    )
    .unwrap();
}

// Should allow Bob to verify Alice's ownership of her identity key based on
// Charlie's public key and signature
fn test_bob_verify_alice_identity(
    b: &Channel,
    charlie_identity_key: Ed25519PublicKey,
    charlie_signature_alice_identity: Ed25519Signature,
) {
    b.verify(
        &charlie_identity_key,
        &charlie_signature_alice_identity,
        None,
    )
    .unwrap();
}

// Should allow Alice to verify Bob's ownership of his identity key based on
// Charlie's public key and signature
fn test_alice_verify_bob_identity(
    a: &Channel,
    charlie_identity_key: Ed25519PublicKey,
    charlie_signature_bob_identity: Ed25519Signature,
) {
    a.verify(&charlie_identity_key, &charlie_signature_bob_identity, None)
        .unwrap();
}

// Should handle out of order messages correctly
fn test_out_of_order_messages(a: &mut Channel, b: &mut Channel) {
    let data1 = vec![1, 2, 3];
    let data2 = vec![4, 5, 6];
    let data3 = vec![7, 8, 9];
    let data4 = vec![10, 11, 12];
    let (_, message1) = a.encrypt(&data1).unwrap();
    let (_, message2) = a.encrypt(&data2).unwrap();
    let (_, message3) = a.encrypt(&data3).unwrap();
    let (_, message4) = a.encrypt(&data4).unwrap();
    let (index4, plaintext4) = b.decrypt(&message4).unwrap();
    let (index2, plaintext2) = b.decrypt(&message2).unwrap();
    let (index3, plaintext3) = b.decrypt(&message3).unwrap();
    let (index1, plaintext1) = b.decrypt(&message1).unwrap();
    // Index start at 2 since another test (test_alice_message_to_bob) that
    // uses the same channel ran before this test
    assert_eq!(index1, 2);
    assert_eq!(index2, 3);
    assert_eq!(index3, 4);
    assert_eq!(index4, 5);
    assert_eq!(plaintext1, data1);
    assert_eq!(plaintext2, data2);
    assert_eq!(plaintext3, data3);
    assert_eq!(plaintext4, data4);
}
