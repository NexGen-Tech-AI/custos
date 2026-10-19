//! CLAUDE.md rule 28: fixtures and docs carry no machine or personal details.
//! Scans every fixture directory and every doc of the repo with the scrub scan
//! (tests/scrub/mod.rs, also run by tools/capture_fixtures.sh on its output).
//! The same checks run locally and on CI: nothing reads the environment.
use std::path::{Path, PathBuf};

mod scrub;
use scrub::{files, machine_tokens, scan, MACHINE_TOKENS};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").canonicalize().unwrap()
}

/// Fixture directories and docs (relative to the repo root).
const FIXTURE_DIRS: &[&str] = &["tests/fixtures", "src/tests/perf/fixtures", "custos-model/tests/fixtures", "docs"];
/// The scrubber itself names what it replaces; the raw snapshots are gitignored
/// (only the scrubbed, trimmed fixture is committed: tests/fixtures/README.md).
const SKIP: &[&str] = &["tests/fixtures/scrub.sh"];
fn local_only(rel: &str) -> bool {
    rel.starts_with("tests/fixtures/aegis_perf_full") || rel.ends_with(".db.tmp")
}
/// Published contacts, kept on purpose: (file, address).
const CONTACTS: &[(&str, &str)] = &[
    ("README.md", "timothy@riffeandassociates.com"),
    ("SECURITY.md", "timothy@riffeandassociates.com"),
    ("docs/archive/BUILD_STATUS.md", "security@custos.ai"),
    ("docs/archive/PROGRESS_SUMMARY.md", "security@custos.ai"),
];

#[test]
fn machine_tokens_match_whole_tokens_only() {
    // A made-up host, "example-host-7", and the real list's digests.
    let list = &[("host name", "709705b52366d63b21bbc0ee46970829f19ebca8a5864c8a87c126b561b90b22")];
    let f = |l: &str| machine_tokens(list, l).len();
    assert_eq!(f("device example-host-7 ok"), 1);
    assert_eq!(f("device EXAMPLE-HOST-7, ok"), 1, "case-insensitive");
    assert_eq!(f("device example-host-7-b ok"), 0, "part of a longer token");
    assert_eq!(f("xexample-host-7"), 0);
    assert_eq!(f("https://github.com/example-host-7/repo"), 0, "a published repo URL");
    assert!(machine_tokens(MACHINE_TOKENS, "runner-up and test runner").is_empty());
}

#[test]
fn fixtures_and_docs_are_scrubbed() {
    let root = repo();
    let mut all = Vec::new();
    for d in FIXTURE_DIRS {
        files(&root.join(d), &mut all);
    }
    for e in std::fs::read_dir(&root).unwrap().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "md") {
            all.push(p);
        }
    }
    all.retain(|p| {
        let rel = p.strip_prefix(&root).unwrap().to_string_lossy();
        !SKIP.contains(&rel.as_ref()) && !local_only(&rel)
    });
    let found = scan(&root, &all, CONTACTS, MACHINE_TOKENS);
    assert!(found.is_empty(), "{} unscrubbed detail(s):\n{}", found.len(), found.join("\n"));
}
