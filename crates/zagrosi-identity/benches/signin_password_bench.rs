// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::expect_used, missing_docs)]

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use zagrosi_identity::password::Argon2idHasher;

mod common;

fn bench_password_verify(c: &mut Criterion) {
    let rt = common::criterion_runtime();
    let hasher = Argon2idHasher::new(&common::bench_argon2_config()).expect("argon2 config");
    let phc = rt
        .block_on(hasher.hash(common::BENCH_PASSWORD))
        .expect("hash bench password");

    let mut group = c.benchmark_group("signin_password_bench");
    group.throughput(Throughput::Elements(1));
    group.bench_function("argon2_verify", |b| {
        b.to_async(&rt).iter(|| async {
            let ok = hasher
                .verify(common::BENCH_PASSWORD, &phc)
                .await
                .expect("verify bench password");
            criterion::black_box(ok);
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(250));
    targets = bench_password_verify
}
criterion_main!(benches);
