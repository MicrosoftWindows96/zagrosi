// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::expect_used, missing_docs)]

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use zagrosi_identity::session::SessionCache;

mod common;

fn bench_session_resolve_cold(c: &mut Criterion) {
    let rt = common::criterion_runtime();
    let mut seed = 1u8;

    let mut group = c.benchmark_group("session_resolve_bench_cold");
    group.throughput(Throughput::Elements(1));
    group.bench_function("insert_get_evict", |b| {
        b.to_async(&rt).iter(|| {
            let cache = SessionCache::new(64, Duration::from_secs(30));
            let (hash, value) = common::cached_session(seed);
            seed = seed.wrapping_add(1).max(1);
            async move {
                cache.insert(hash, value.clone()).await;
                let got = cache.get(&hash).await.expect("cold cache fill");
                let evicted = cache.evict_by_session_id(value.session_id).await;
                criterion::black_box((got, evicted));
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
    targets = bench_session_resolve_cold
}
criterion_main!(benches);
