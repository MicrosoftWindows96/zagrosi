// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::expect_used, missing_docs)]

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

mod common;

const OIDC_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/bench/oidc_id_token.json");

fn bench_oidc_callback_fixture(c: &mut Criterion) {
    let mut group = c.benchmark_group("signin_oidc_callback_bench");
    group.throughput(Throughput::Elements(1));
    group.bench_function("fixture_decode", |b| {
        b.iter(|| {
            let fixture = common::decode_oidc_fixture(OIDC_FIXTURE);
            criterion::black_box(fixture);
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
    targets = bench_oidc_callback_fixture
}
criterion_main!(benches);
