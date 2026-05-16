// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::expect_used, missing_docs)]

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

mod common;

fn bench_session_resolve_warm(c: &mut Criterion) {
    let rt = common::criterion_runtime();
    let (cache, hashes) = rt.block_on(common::warm_session_cache(256));
    let mut index = 0usize;

    let mut group = c.benchmark_group("session_resolve_bench");
    group.throughput(Throughput::Elements(1));
    group.bench_function("warm_cache_get", |b| {
        b.to_async(&rt).iter(|| {
            let hash = hashes[index % hashes.len()];
            index = index.wrapping_add(1);
            let cache = cache.clone();
            async move {
                let got = cache.get(&hash).await.expect("warm cache hit");
                criterion::black_box(got);
            }
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(300));
    targets = bench_session_resolve_warm
}
criterion_main!(benches);
