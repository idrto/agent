use criterion::{criterion_group, criterion_main, Criterion};

fn bench_dedup(_c: &mut Criterion) {}

criterion_group!(benches, bench_dedup);
criterion_main!(benches);
