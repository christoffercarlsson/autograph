use autograph::{
    authenticate, issue, key_exchange, key_pair, receive, send, verify, verify_key_exchange,
    Channel, Ed25519Signer, Signer,
};
use criterion::{criterion_group, criterion_main, Criterion};

pub fn benchmark(c: &mut Criterion) {
    let signer = Signer::from([
        51, 45, 77, 34, 55, 79, 178, 70, 245, 26, 9, 86, 12, 200, 101, 230, 7, 253, 207, 52, 39,
        155, 55, 88, 138, 98, 168, 237, 13, 228, 108, 85,
    ]);

    let our_identity_key = signer.public_key().unwrap();

    let our_id = [10, 168, 165, 73, 24, 165, 2, 173, 121, 222, 4];

    let (our_private_key, our_public_key) = key_pair([
        136, 157, 80, 54, 187, 219, 65, 70, 252, 214, 35, 87, 11, 147, 73, 212, 4, 135, 30, 229,
        37, 30, 185, 243, 3, 212, 39, 116, 93, 181, 30, 226,
    ]);

    let their_identity_key = [
        245, 232, 159, 96, 146, 237, 36, 130, 64, 81, 235, 154, 94, 36, 63, 126, 98, 213, 79, 208,
        118, 252, 237, 227, 86, 199, 16, 53, 161, 17, 166, 252,
    ];

    let their_id = [203, 73, 15, 32, 33, 24, 90, 201, 55, 209, 207];

    let their_public_key = [
        188, 168, 202, 61, 41, 90, 221, 99, 209, 240, 124, 231, 58, 159, 217, 6, 190, 211, 168,
        168, 137, 255, 241, 32, 1, 49, 229, 153, 48, 215, 178, 16,
    ];

    let secret_key = [
        227, 196, 77, 171, 107, 204, 201, 156, 16, 26, 166, 146, 69, 164, 105, 109, 183, 249, 11,
        242, 156, 251, 153, 0, 22, 5, 144, 181, 28, 204, 42, 134,
    ];

    let their_signature = [
        214, 33, 245, 222, 44, 178, 77, 196, 54, 102, 203, 189, 48, 220, 157, 85, 116, 44, 47, 230,
        68, 51, 215, 210, 93, 118, 220, 139, 251, 96, 129, 248, 234, 23, 45, 96, 249, 78, 31, 31,
        1, 59, 50, 232, 151, 186, 168, 51, 91, 138, 59, 115, 45, 20, 253, 114, 18, 165, 176, 10,
        84, 255, 240, 7,
    ];

    let mut channel = Channel::new(&secret_key, &our_id, &their_id);

    let data = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

    let credential_message = [
        0, 0, 0, 1, 16, 126, 98, 217, 210, 113, 99, 188, 218, 117, 22, 211, 221, 241, 13, 7, 237,
        94, 43, 231, 248, 40, 209, 82, 253, 69, 176, 89, 5, 187, 92, 180, 142, 195, 57, 220, 189,
        200, 31, 205, 131, 93, 111, 90, 142, 242, 51, 161, 109, 255, 226, 43, 94, 122, 129, 206,
        227, 149, 50, 184, 123, 204, 33, 228, 87, 81, 63, 192, 226, 80, 39, 16, 26, 64, 67, 180,
        145, 29, 47, 64, 145, 42, 160, 79, 32, 5, 30, 72, 48, 50, 171, 178, 87, 175, 175, 102, 146,
        60, 38, 206, 88, 42, 135, 114, 128, 15, 216, 242, 28, 113, 14, 87,
    ];

    c.bench_function("authenticate", |b| {
        b.iter(|| authenticate(&signer, &our_id, &their_identity_key, &their_id))
    });

    c.bench_function("key_exchange", |b| {
        b.iter(|| {
            key_exchange(
                &signer,
                &our_private_key,
                &our_public_key,
                &their_identity_key,
                &their_public_key,
                None,
            )
        })
    });

    c.bench_function("verify_key_exchange", |b| {
        b.iter(|| {
            verify_key_exchange(
                &signer,
                &our_public_key,
                &their_identity_key,
                &their_public_key,
                &their_signature,
            )
        })
    });

    c.bench_function("encrypt", |b| {
        b.iter(|| {
            let mut buffer = [72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];
            channel.encrypt(&mut buffer, None).unwrap();
        })
    });

    c.bench_function("decrypt", |b| {
        b.iter(|| {
            let mut buffer = [173, 243, 145, 213, 47, 188, 16, 81, 232, 72, 153];
            let tag = [
                196, 6, 5, 62, 27, 165, 207, 48, 55, 225, 51, 199, 152, 19, 23, 80,
            ];
            channel.decrypt(1, &mut buffer, &tag, None).unwrap();
        })
    });

    c.bench_function("issue", |b| {
        b.iter(|| issue(&signer, &their_identity_key, Some(&data), &mut channel))
    });

    c.bench_function("send", |b| {
        b.iter(|| {
            let signature = [
                233, 94, 51, 63, 113, 160, 155, 151, 122, 8, 156, 147, 253, 73, 95, 248, 128, 106,
                195, 8, 37, 27, 176, 185, 83, 172, 233, 32, 124, 12, 146, 146, 7, 250, 54, 140,
                251, 204, 199, 34, 189, 1, 255, 33, 54, 85, 168, 196, 93, 110, 202, 137, 99, 184,
                38, 151, 204, 80, 147, 82, 20, 35, 102, 11,
            ];
            send(&our_identity_key, &signature, &mut channel).unwrap();
        })
    });

    c.bench_function("verify", |b| {
        b.iter(|| {
            verify(
                &our_identity_key,
                Some(&data),
                &channel,
                &credential_message,
            )
        })
    });

    c.bench_function("receive", |b| {
        b.iter(|| receive(&credential_message, &channel))
    });
}

criterion_group!(benchmarks, benchmark);
criterion_main!(benchmarks);
