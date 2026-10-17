//! Print compare() of two builds as JSON:
//!     cargo run --example compare -- SHA_A SHA_B
use anyhow::{bail, Result};
use custos_perf::{Filter, Sources};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [a, b] = &args[..] else { bail!("usage: compare SHA_A SHA_B") };
    let src = Sources::from_env();
    let con = src.open()?;
    println!("{}", serde_json::to_string_pretty(&custos_perf::compare(&con, a, b, &Filter::default())?)?);
    Ok(())
}
