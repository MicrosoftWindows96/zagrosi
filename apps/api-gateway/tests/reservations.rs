// SPDX-License-Identifier: AGPL-3.0-or-later

//! Filesystem-level tests for reserved app directories.
//!
//! These tests guard the workspace-glob hazard (R25): a `.gitkeep`-only
//! directory under `apps/` must never accidentally become a workspace member,
//! and the reserved app slot list must stay exactly three (`zagrosi-mcp`,
//! `worker`, `web`). `apps/admin` is intentionally absent; the MVP admin
//! surface ships inside `apps/web` until a later split decides otherwise.

use std::path::Path;

// `CARGO_MANIFEST_DIR` is `<repo>/apps/api-gateway`; the repo root is two
// parents up. `concat!` joins at compile time so no runtime fallibility is
// involved; the OS resolves `..` segments during the actual filesystem
// lookup performed by each test.
const WORKSPACE_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

fn workspace_root() -> &'static Path {
    Path::new(WORKSPACE_ROOT)
}

#[test]
fn reserved_dirs_have_only_gitkeep() {
    let root = workspace_root();
    for reserved in ["apps/zagrosi-mcp", "apps/worker", "apps/web"] {
        let dir = root.join(reserved);
        assert!(dir.is_dir(), "{reserved} must exist as a directory");

        // Reserved dirs must contain exactly one entry: `.gitkeep`. Anything
        // else risks accidentally promoting the directory to a workspace
        // member (Cargo.toml), a pnpm package (package.json), or a stray
        // build artefact. Enumerate explicitly rather than checking only
        // for `Cargo.toml` and `package.json` absence.
        let entries: Vec<String> = std::fs::read_dir(&dir)
            .unwrap_or_else(|err| panic!("{reserved} must be readable: {err}"))
            .map(|entry| {
                let entry =
                    entry.unwrap_or_else(|err| panic!("{reserved} entry must be readable: {err}"));
                entry.file_name().to_string_lossy().into_owned()
            })
            .collect();

        assert_eq!(
            entries,
            vec![".gitkeep".to_owned()],
            "{reserved} must contain exactly `.gitkeep` and nothing else; found {entries:?}",
        );
    }
}

#[test]
fn apps_admin_does_not_exist() {
    let admin = workspace_root().join("apps/admin");
    assert!(
        !admin.exists(),
        "apps/admin must not exist; admin surface ships inside apps/web for the MVP",
    );
}

#[test]
fn no_premature_crate_reservations() {
    let crates_dir = workspace_root().join("crates");
    assert!(crates_dir.is_dir(), "crates/ directory must exist");

    // Loud failure on unreadable entries; silent skipping would let a
    // permission glitch hide a real `.gitkeep`-only reservation.
    let read = std::fs::read_dir(&crates_dir).expect("crates/ must be readable");
    for entry in read {
        let entry = entry.expect("crates/ entry must be readable");
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let cargo_toml = path.join("Cargo.toml");
        assert!(
            cargo_toml.is_file(),
            "{} must contain Cargo.toml (no .gitkeep-only crate reservations allowed)",
            path.display(),
        );
    }
}
