use autograph_protocol::{
    key_exchange, verify_key_exchange, Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature,
    X25519KeyPair, X25519PublicKey,
};
use criterion::Criterion;

pub fn benchmark(c: &mut Criterion) {
    let our_identity_key_pair: Ed25519KeyPair = [
        118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2, 56, 252, 122, 177,
        18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17, 213, 153, 88, 124, 93, 136, 104,
        111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243,
        24, 225, 91, 220, 141, 150,
    ];

    let our_session_key_pair: X25519KeyPair = [
        201, 142, 54, 248, 151, 150, 224, 79, 30, 126, 207, 157, 118, 85, 9, 212, 148, 156, 73,
        176, 107, 107, 47, 111, 95, 98, 33, 192, 80, 223, 48, 221, 35, 16, 23, 37, 205, 131, 166,
        97, 13, 81, 136, 246, 193, 253, 139, 193, 230, 155, 222, 221, 37, 114, 190, 87, 104, 44,
        210, 144, 127, 176, 198, 45,
    ];

    let their_identity_key: Ed25519PublicKey = [
        177, 67, 45, 125, 158, 190, 181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61, 200,
        62, 29, 37, 150, 228, 137, 114, 143, 77, 115, 135, 143, 103,
    ];

    let their_session_key: X25519PublicKey = [
        88, 115, 171, 4, 34, 181, 120, 21, 10, 39, 204, 215, 158, 210, 177, 243, 28, 138, 52, 91,
        236, 55, 30, 117, 10, 125, 87, 232, 80, 6, 232, 93,
    ];

    let their_signature: Ed25519Signature = [
        22, 51, 47, 208, 198, 143, 141, 242, 199, 185, 82, 142, 190, 105, 55, 152, 145, 185, 67,
        35, 122, 253, 201, 23, 74, 40, 110, 217, 60, 198, 123, 216, 195, 74, 74, 185, 65, 215, 2,
        151, 214, 117, 91, 122, 16, 145, 253, 88, 26, 50, 135, 226, 45, 126, 125, 22, 88, 214, 178,
        147, 69, 72, 143, 3,
    ];

    c.bench_function("key_exchange", |b| {
        b.iter(|| {
            key_exchange(
                &our_identity_key_pair,
                &our_session_key_pair,
                &their_identity_key,
                &their_session_key,
            )
            .unwrap()
        })
    });

    c.bench_function("verify_key_exchange", |b| {
        b.iter(|| {
            verify_key_exchange(
                &our_identity_key_pair,
                &our_session_key_pair,
                &their_identity_key,
                &their_session_key,
                &their_signature,
            )
            .unwrap()
        })
    });
}
