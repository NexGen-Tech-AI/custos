//! CLAUDE.md rule 28: fixtures and docs carry no machine or personal details.
//! Scans every fixture directory and every doc of the repo (text files as
//! text; SQLite files by their strings; PNG files by their text chunks, since
//! pixels cannot be read here) for: the development machines' host and user
//! names (whole tokens, against a fixed list of digests); home-directory paths;
//! IPv4 addresses other than loopback; IPv6 link-local addresses; e-mail
//! addresses; access tokens; environment variables set to absolute paths.
use std::path::{Path, PathBuf};

use regex::Regex;

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

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Printable runs of 4+ bytes (like strings(1)).
fn strings(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut run = String::new();
    for &b in bytes {
        if (0x20..0x7f).contains(&b) {
            run.push(b as char);
        } else {
            if run.len() >= 4 {
                out.push_str(&run);
                out.push('\n');
            }
            run.clear();
        }
    }
    out + &run
}

/// tEXt / iTXt / zTXt chunk payloads of a PNG (metadata; pixels are not text).
fn png_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 8;
    while i + 8 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[i..i + 4].try_into().unwrap()) as usize;
        let kind = &bytes[i + 4..i + 8];
        let end = (i + 8 + len).min(bytes.len());
        if matches!(kind, b"tEXt" | b"iTXt" | b"zTXt") {
            out += &strings(&bytes[i + 8..end]);
        }
        i = end + 4;
    }
    out
}

fn text_of(p: &Path) -> String {
    let bytes = std::fs::read(p).unwrap();
    match p.extension().and_then(|e| e.to_str()) {
        Some("png") => png_text(&bytes),
        Some("db" | "sqlite") => strings(&bytes),
        _ => match String::from_utf8(bytes.clone()) {
            Ok(s) => s,
            Err(_) => strings(&bytes),
        },
    }
}

/// Host and user names of the development machines, as SHA-256 digests of the
/// lower-cased name (so the repo never spells them out). Fixed, so the check is
/// the same on every machine and on CI. Add a machine with
/// `printf %s "$(hostname)" | tr A-Z a-z | sha256sum` (and the same for `id -un`).
const MACHINE_TOKENS: &[(&str, &str)] = &[
    ("host name", "9e75ed1094b459c44f5543d656f4770f022ec1d58860e90b799eba331fdb97e6"),
    ("user name", "978c3225f01d987a5a3e6d68f84bc2c3b0d0cb7510d23ab2affcabf6ba0e4de5"),
];
/// The repository owner's account, published in the repo's own URLs.
const PUBLISHED_PREFIXES: &[&str] = &["github.com/"];

fn sha256_hex(s: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// Whole tokens of a line: maximal runs of host / user-name characters
/// ([A-Za-z0-9._-]), with their byte offsets. "runner-up" is one token, never
/// "runner".
fn tokens(line: &str) -> impl Iterator<Item = (usize, &str)> {
    let is_tok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in line.char_indices().chain(std::iter::once((line.len(), ' '))) {
        match (is_tok(c), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                out.push((s, &line[s..i]));
                start = None;
            }
            _ => {}
        }
    }
    out.into_iter()
}

/// Hits of a digest list in one line: (which, token).
fn machine_tokens(list: &[(&'static str, &str)], line: &str) -> Vec<(&'static str, String)> {
    let mut hits = Vec::new();
    for (at, tok) in tokens(line) {
        let digest = sha256_hex(&tok.to_ascii_lowercase());
        if let Some((name, _)) = list.iter().find(|(_, d)| *d == digest) {
            if !PUBLISHED_PREFIXES.iter().any(|p| line[..at].to_ascii_lowercase().ends_with(p)) {
                hits.push((*name, tok.to_string()));
            }
        }
    }
    hits
}

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
    let patterns: Vec<(&str, Regex)> = [
        ("home path", r"(/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|[A-Za-z]:\\Users\\|(^|[\s`'(=])~/)"),
        ("IPv4 address", r"\b(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"),
        ("IPv6 link-local address", r"(?i)\bfe80::[0-9a-f:]+"),
        ("e-mail address", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z]{2,}\b"),
        ("access token", r"(ghp_|gho_|github_pat_|xox[bp]-|AKIA[0-9A-Z]{16}|(?i:bearer\s+[a-z0-9._-]{16,})|(?i:(token|password|secret)=\S+))"),
        ("environment variable with a path", r"\b[A-Z][A-Z0-9_]{2,}=/[^\s]+"),
    ]
    .into_iter()
    .map(|(n, r)| (n, Regex::new(r).unwrap()))
    .collect();
    // Loopback, and the RFC 5737 documentation ranges (examples in docs).
    let allowed_ip = |ip: &str| ["127.0.0.1", "0.0.0.0"].contains(&ip) || ["192.0.2.", "198.51.100.", "203.0.113."].iter().any(|r| ip.starts_with(r));
    // Published contacts, kept on purpose: (file, address).
    const CONTACTS: &[(&str, &str)] = &[
        ("README.md", "timothy@riffeandassociates.com"),
        ("SECURITY.md", "timothy@riffeandassociates.com"),
        ("docs/archive/BUILD_STATUS.md", "security@custos.ai"),
        ("docs/archive/PROGRESS_SUMMARY.md", "security@custos.ai"),
    ];
    let mut found = Vec::new();
    for p in &all {
        let rel = p.strip_prefix(&root).unwrap().to_string_lossy().into_owned();
        if SKIP.contains(&rel.as_str()) || local_only(&rel) {
            continue;
        }
        let text = text_of(p);
        for (line_no, line) in text.lines().enumerate() {
            for (name, re) in &patterns {
                for m in re.find_iter(line) {
                    if *name == "IPv4 address" && allowed_ip(m.as_str()) {
                        continue;
                    }
                    if *name == "e-mail address" && CONTACTS.contains(&(rel.as_str(), m.as_str())) {
                        continue;
                    }
                    found.push(format!("{rel}:{}: {name}: {}", line_no + 1, m.as_str().trim()));
                }
            }
            for (name, _) in machine_tokens(MACHINE_TOKENS, line) {
                found.push(format!("{rel}:{}: a development machine's {name}", line_no + 1));
            }
        }
    }
    assert!(found.is_empty(), "{} unscrubbed detail(s):\n{}", found.len(), found.join("\n"));
}
