use autograph_protocol::{generate_identity_key_pair, generate_session_key_pair};
use criterion::Criterion;
use rand::rngs::OsRng;

pub fn benchmark(c: &mut Criterion) {
    c.bench_function("identity_key_pair", |b| {
        b.iter(|| generate_identity_key_pair(OsRng).unwrap())
    });

    c.bench_function("session_key_pair", |b| {
        b.iter(|| generate_session_key_pair(OsRng).unwrap())
    });
}
