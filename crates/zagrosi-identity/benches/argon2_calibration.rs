// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::expect_used, missing_docs)]

use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use zagrosi_identity::password::{Argon2idHasher, calibrate};

mod common;

fn bench_argon2_calibration(c: &mut Criterion) {
    let rt = common::criterion_runtime();
    let hasher = Argon2idHasher::new(&common::bench_argon2_config()).expect("argon2 config");

    c.bench_function("argon2_calibration", |b| {
        b.to_async(&rt).iter(|| calibrate(&hasher));
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(250));
    targets = bench_argon2_calibration
}
criterion_main!(benches);
