// SPDX-License-Identifier: AGPL-3.0-or-later

//! Self-test for the standards conformance map in `documentation/identity.md`.

use std::collections::BTreeSet;
use std::path::PathBuf;

#[test]
fn every_cited_test_file_exists() {
    let root = repo_root();
    let doc = std::fs::read_to_string(root.join("documentation/identity.md"))
        .unwrap_or_else(|err| panic!("read identity docs: {err}"));
    let Some((_, rest)) = doc.split_once("## Standards Conformance Map") else {
        panic!("missing standards conformance map");
    };
    let section = rest.split("\n## ").next().unwrap_or(rest);
    let mut missing = Vec::new();
    let mut seen = BTreeSet::new();

    for token in section.split(|c: char| c.is_whitespace() || c == '`' || c == '|') {
        let citation = token.trim_matches(|c: char| c == ',' || c == '.' || c == ')' || c == '(');
        let Some(rs_index) = citation.find(".rs") else {
            continue;
        };
        let path_end = rs_index + ".rs".len();
        let path_part = &citation[..path_end];
        if !path_part.starts_with("crates/") {
            continue;
        }
        let fn_part = citation[path_end..].strip_prefix("::");
        let key = format!("{path_part}::{fn_part:?}");
        if !seen.insert(key) {
            continue;
        }
        let path = root.join(path_part);
        if !path.is_file() {
            missing.push(path.display().to_string());
            continue;
        }
        if let Some(function) = fn_part {
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|err| panic!("read cited file {}: {err}", path.display()));
            let needle = function.to_owned();
            if !body.contains(&needle) {
                missing.push(format!("{} missing {needle}", path.display()));
            }
        }
    }

    assert!(seen.len() >= 10, "standards map has too few citations");
    assert!(
        missing.is_empty(),
        "standards map cites missing test files: {missing:#?}"
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf)
}
