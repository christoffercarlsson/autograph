use criterion::{criterion_group, criterion_main};

mod auth;
mod cert;
mod key_exchange;
mod message;

criterion_group!(
    benchmarks,
    auth::benchmark,
    cert::benchmark,
    key_exchange::benchmark,
    message::benchmark
);
criterion_main!(benchmarks);
