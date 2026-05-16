// SPDX-License-Identifier: AGPL-3.0-or-later

#![cfg(feature = "saml")]
#![allow(clippy::expect_used, missing_docs)]

use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};

mod common;

const SAML_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/bench/saml_assertion.xml");

fn bench_saml_acs_fixture(c: &mut Criterion) {
    let mut group = c.benchmark_group("signin_saml_acs_bench");
    group.throughput(Throughput::Elements(1));
    group.bench_function("fixture_parse", |b| {
        b.iter(|| {
            let xml = common::decode_saml_fixture(SAML_FIXTURE);
            zagrosi_identity::saml::acs::fuzz_entry(xml.as_bytes());
            criterion::black_box(xml);
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
    targets = bench_saml_acs_fixture
}
criterion_main!(benches);
