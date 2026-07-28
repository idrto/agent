use criterion::{criterion_group, criterion_main, Criterion};

fn bench_table(_c: &mut Criterion) {}

criterion_group!(benches, bench_table);
criterion_main!(benches);
