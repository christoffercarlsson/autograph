use autograph_protocol::authenticate;
use criterion::Criterion;

pub fn benchmark(c: &mut Criterion) {
    let our_identity_key_pair = vec![
        118, 164, 17, 240, 147, 79, 190, 38, 66, 93, 254, 238, 125, 202, 197, 2, 56, 252, 122, 177,
        18, 187, 249, 208, 29, 149, 122, 103, 57, 199, 19, 17, 213, 153, 88, 124, 93, 136, 104,
        111, 196, 208, 155, 156, 165, 31, 120, 186, 79, 205, 247, 175, 243, 184, 114, 80, 152, 243,
        24, 225, 91, 220, 141, 150,
    ];
    let their_identity_key = vec![
        177, 67, 45, 125, 158, 190, 181, 222, 101, 149, 224, 200, 223, 235, 222, 110, 67, 61, 200,
        62, 29, 37, 150, 228, 137, 114, 143, 77, 115, 135, 143, 103,
    ];
    c.bench_function("authenticate", |b| {
        b.iter(|| authenticate(&our_identity_key_pair, &their_identity_key).unwrap())
    });
}
