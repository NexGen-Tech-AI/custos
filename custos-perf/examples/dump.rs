//! Print a perf command's JSON, as the Tauri app returns it:
//!     cargo run --example dump -- devices | arch_model SM | roofline SM | winners SM
//! Used to refresh the frontend test fixtures (src/tests/perf/fixtures/).
use anyhow::{bail, Result};
use custos_perf::Sources;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let src = Sources::from_env();
    let con = src.open()?;
    let sm = || -> Result<i64> { Ok(args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(121)) };
    let json = match args.first().map(String::as_str) {
        Some("devices") => serde_json::to_string_pretty(&custos_perf::devices(&src, &con)?)?,
        Some("arch_model") => serde_json::to_string_pretty(&custos_perf::arch_model(&src, &con, sm()?)?)?,
        Some("roofline") => serde_json::to_string_pretty(&custos_perf::roofline(&src, &con, sm()?)?)?,
        Some("winners") => serde_json::to_string_pretty(&custos_perf::winners(&src, &con, sm()?)?)?,
        _ => bail!("usage: dump devices | arch_model SM | roofline SM | winners SM"),
    };
    println!("{json}");
    Ok(())
}
