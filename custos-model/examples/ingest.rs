//! Print the normalized model of a recorded output, with provenance:
//!   cargo run --example ingest -- nsys EXPORT.sqlite
//!   cargo run --example ingest -- ncu DIR STEM     (DIR/STEM.details.csv, .raw.csv, .session.csv)
use custos_model::{ncu, nsys};

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let c = match a.first().map(String::as_str) {
        Some("nsys") => nsys::ingest(std::path::Path::new(&a[1]))?,
        Some("ncu") => ncu::ingest(&ncu::NcuCsv::load(std::path::Path::new(&a[1]), &a[2])?)?,
        _ => anyhow::bail!("usage: ingest nsys EXPORT | ingest ncu DIR STEM"),
    };
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "devices": c.devices, "runs": c.runs, "kernels": c.kernels, "launches": c.launches,
        "counters": c.counters.len(), "counter_sample": c.counters.iter().take(3).collect::<Vec<_>>(),
        "timeline_events": c.timelines.iter().map(|t| t.events.len()).sum::<usize>(),
        "notes": c.notes, "contract_violations": custos_model::contract::violations(&c),
    }))?);
    Ok(())
}
