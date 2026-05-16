// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_panics_doc,
    clippy::missing_const_for_fn
)]
//! Path helpers for the section-16 negative-corpus fixtures under
//! `crates/zagrosi-identity/tests/fixtures/`.
//!
//! The corpora are committed bytes (see
//! `tests/fixtures/negative/saml/.GENERATOR.md` for the construction
//! recipe). These helpers resolve paths relative to
//! `CARGO_MANIFEST_DIR` so the suites and the
//! `scripts/seed-fuzz-corpus.sh` seeding stay in lock-step.

use std::path::PathBuf;

/// `crates/zagrosi-identity/tests/fixtures`.
#[must_use]
pub fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

/// `tests/fixtures/negative/<protocol>`.
#[must_use]
pub fn negative_root(protocol: &str) -> PathBuf {
    fixtures_root().join("negative").join(protocol)
}

/// Absolute path to a committed SAML negative-corpus fixture.
#[must_use]
pub fn negative_saml(name: &str) -> PathBuf {
    negative_root("saml").join(name)
}

/// Absolute path to a committed OIDC negative-corpus fixture.
#[must_use]
pub fn negative_oidc(name: &str) -> PathBuf {
    negative_root("oidc").join(name)
}

/// Absolute path to a committed SCIM negative-corpus fixture.
#[must_use]
pub fn negative_scim(name: &str) -> PathBuf {
    negative_root("scim").join(name)
}

/// Read a SAML negative fixture as raw bytes.
///
/// # Panics
///
/// Panics if the committed fixture is missing — a missing corpus
/// file is a checkout / generator-script regression, not a runtime
/// condition, so failing loudly is correct here.
#[must_use]
pub fn read_negative_saml(name: &str) -> Vec<u8> {
    let path = negative_saml(name);
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing committed SAML fixture {}: {e}", path.display()))
}

/// Read every committed SCIM `filter_invalid_*.txt` line-by-line as
/// `(fixture_name, filter_string)` pairs. Each file holds one
/// adversarial filter per line; blank lines and `#` comments are
/// skipped so the corpus stays self-documenting.
#[must_use]
pub fn scim_invalid_filters() -> Vec<(String, String)> {
    let dir = negative_root("scim");
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return out;
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                n.starts_with("filter_invalid_")
                    && std::path::Path::new(n)
                        .extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"))
            })
        })
        .collect();
    files.sort();
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if let Ok(body) = std::fs::read_to_string(&path) {
            for line in body.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                out.push((name.clone(), line.to_string()));
            }
        }
    }
    out
}
