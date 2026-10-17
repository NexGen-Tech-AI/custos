//! Print a perf command's JSON, as the Tauri app returns it:
//!     cargo run --example dump -- devices | arch_model SM | roofline SM | winners SM
//!         | kernel KERNEL_ID [SASS_LINES]
//! (kernel: SASS_LINES keeps only the first lines of each listing, to keep a
//! test fixture small; `lines` still gives the listing's full length.)
//! Used to refresh the frontend test fixtures (src/tests/perf/fixtures/) from
//! the repo fixtures (no AEGIS_CORE set). Paths under the repo root are
//! printed relative to it, so the output does not depend on the checkout.
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
        Some("kernel") => {
            let Some(id) = args.get(1) else { bail!("usage: dump kernel KERNEL_ID [SASS_LINES]") };
            let mut k = custos_perf::kernel_detail(&src, &con, id)?;
            if let (Some(k), Some(n)) = (k.as_mut(), args.get(2)) {
                let n: usize = n.parse()?;
                for s in k.artifacts.iter_mut().filter_map(|a| a.sass.as_mut()) {
                    s.text = s.text.lines().take(n).collect::<Vec<_>>().join("\n");
                }
            }
            serde_json::to_string_pretty(&k)?
        }
        _ => bail!("usage: dump devices | arch_model SM | roofline SM | winners SM | kernel KERNEL_ID [SASS_LINES]"),
    };
    let repo = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").canonicalize()?;
    println!("{}", json.replace(&format!("{}/", repo.display()), ""));
    Ok(())
}
