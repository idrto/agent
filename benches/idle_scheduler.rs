use criterion::{criterion_group, criterion_main, Criterion};

fn bench_idle(_c: &mut Criterion) {}

criterion_group!(benches, bench_idle);
criterion_main!(benches);
