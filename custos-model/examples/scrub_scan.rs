//! The scrub scan (CLAUDE.md rule 28) over any directories, e.g. a capture's
//! output before it is committed (tools/capture_fixtures.sh runs it):
//!
//!   cargo run --manifest-path custos-model/Cargo.toml --example scrub_scan -- [--this-machine] DIR...
//!
//! `--this-machine` also looks for the running machine's host and user names
//! (whole tokens), for a machine not in the fixed list. Prints each unscrubbed
//! detail and exits 1 when there is any.
#[path = "../tests/scrub/mod.rs"]
mod scrub;

use std::path::Path;

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let this_machine = args.iter().any(|a| a == "--this-machine");
    args.retain(|a| a != "--this-machine");
    if args.is_empty() {
        eprintln!("usage: scrub_scan [--this-machine] DIR...");
        std::process::exit(2);
    }
    let mut digests: Vec<(&'static str, String)> = scrub::MACHINE_TOKENS.iter().map(|(n, d)| (*n, d.to_string())).collect();
    if this_machine {
        let host = std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
        let user = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).unwrap_or_default();
        for (name, v) in [("host name", host), ("user name", user)] {
            if !v.is_empty() {
                digests.push((name, scrub::sha256_hex(&v.to_ascii_lowercase())));
            }
        }
    }
    let machines: Vec<(&'static str, &str)> = digests.iter().map(|(n, d)| (*n, d.as_str())).collect();
    let mut found = Vec::new();
    let mut n = 0;
    for d in &args {
        let dir = Path::new(d);
        let mut all = Vec::new();
        scrub::files(dir, &mut all);
        n += all.len();
        found.extend(scrub::scan(dir, &all, &[], &machines).into_iter().map(|f| format!("{d}/{f}")));
    }
    for f in &found {
        println!("{f}");
    }
    if found.is_empty() {
        eprintln!("scrub scan: {n} file(s), clean");
    } else {
        eprintln!("scrub scan: {} unscrubbed detail(s) in {n} file(s)", found.len());
        std::process::exit(1);
    }
}
