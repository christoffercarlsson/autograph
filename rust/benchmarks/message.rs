use autograph_protocol::{decrypt, encrypt};
use criterion::{black_box, Criterion};

pub fn benchmark(c: &mut Criterion) {
    let key = vec![
        228, 80, 92, 70, 9, 154, 102, 79, 79, 238, 183, 1, 104, 239, 123, 93, 228, 74, 44, 60, 147,
        21, 105, 30, 217, 135, 107, 104, 104, 117, 50, 116,
    ];

    let plaintext = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

    let ciphertext = vec![
        253, 199, 105, 203, 139, 136, 132, 228, 198, 157, 65, 140, 116, 90, 212, 112, 55, 190, 186,
        221, 205, 80, 46, 24, 161, 117, 201, 113, 133, 213, 29, 105,
    ];

    c.bench_function("encrypt", |b| {
        b.iter(|| {
            let mut nonce = [0; 12];
            encrypt(&key, black_box(&mut nonce), &plaintext).unwrap()
        })
    });

    c.bench_function("decrypt", |b| {
        b.iter(|| {
            let mut nonce = [0; 12];
            let mut skipped_indexes = vec![0; 512];
            decrypt(
                &key,
                black_box(&mut nonce),
                black_box(&mut skipped_indexes),
                &ciphertext,
            )
            .unwrap()
        })
    });
}
