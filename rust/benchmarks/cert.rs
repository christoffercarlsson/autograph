use core::panic;

use autograph_protocol::{certify, verify};
use criterion::Criterion;

pub fn benchmark(c: &mut Criterion) {
    let our_identity_key_pair = vec![
        118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2, 56, 252, 122, 177,
        18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17, 213, 153, 88, 124, 93, 136, 104,
        111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243,
        24, 225, 91, 220, 141, 150,
    ];
    let their_identity_key = vec![
        129, 128, 10, 70, 174, 223, 175, 90, 43, 37, 148, 125, 188, 163, 110, 136, 15, 246, 192,
        76, 167, 8, 26, 149, 219, 223, 83, 47, 193, 159, 6, 3,
    ];

    let data = vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100];

    let our_identity_key = vec![
        213, 153, 88, 124, 93, 136, 104, 111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247,
        175, 243, 184, 114, 80, 152, 243, 24, 225, 91, 220, 141, 150,
    ];

    let signature = vec![
        231, 126, 138, 39, 145, 83, 130, 243, 2, 56, 53, 185, 199, 242, 217, 239, 118, 208, 172, 6,
        201, 132, 94, 179, 57, 59, 160, 23, 150, 221, 67, 122, 176, 56, 160, 63, 7, 161, 169, 101,
        240, 97, 108, 137, 142, 99, 197, 44, 179, 142, 37, 4, 135, 162, 118, 160, 119, 245, 234,
        39, 26, 75, 71, 6,
    ];

    c.bench_function("certify", |b| {
        b.iter(|| certify(&our_identity_key_pair, &their_identity_key, Some(&data)).unwrap())
    });

    c.bench_function("verify", |b| {
        b.iter(|| {
            if !verify(
                &our_identity_key,
                &their_identity_key,
                &signature,
                Some(&data),
            ) {
                panic!("Signature verification failed");
            }
        })
    });
}
