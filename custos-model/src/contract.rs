//! The data contract (CLAUDE.md rules 1-12, and the profiler-timing rule),
//! enforced on the model. Rules about access and code (1 read-only, 12's
//! "from Core", 17 SQL in aegis-perf) are the adapters' and the build's job;
//! the rest are properties of the values themselves and are checked here,
//! so a view built on the model cannot show what Core has disowned.
use serde::Serialize;

use crate::model::{Capture, Value};
use crate::provenance::{ClockControl, Pairing, RoofOrigin, Source};

/// Largest M held to the read-bandwidth roof (rule 4; aegis_perf::params::DECODE_MAX_M).
pub const DECODE_MAX_M: i64 = 16;

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Violation {
    /// "2".."11", or "P" for the profiler-timing rule.
    pub rule: &'static str,
    pub what: String,
}

fn v(rule: &'static str, what: String) -> Violation {
    Violation { rule, what }
}

/// Every contract violation in a capture; empty when it may be shown.
pub fn violations(c: &Capture) -> Vec<Violation> {
    let mut out = Vec::new();

    for m in &c.measurements {
        let at = format!("measurement {} {:?} (run {})", m.impl_, m.shape, m.run);
        // P: performance results come from the source's own protocol, never a profiler.
        if m.provenance.source.is_profiler() {
            out.push(v("P", format!("{at}: a {:?} timing presented as a measurement", m.provenance.source)));
        }
        // 2 / 7: default filters, or an exclusion shown with its reason.
        match &m.provenance.aegis {
            Some(a) if m.exclusion.is_none() && !a.default_view() => {
                out.push(v("2", format!("{at}: shown by default but {a:?}")))
            }
            None if m.provenance.source == Source::Aegis => out.push(v("2", format!("{at}: AEGIS row without its row state"))),
            _ => {}
        }
    }

    for k in &c.comparisons {
        let at = format!("comparison {} {:?} (run {})", k.kernel, k.shape, k.run);
        // 5: the baseline is cublaslt_best.
        if k.baseline != "cublaslt_best" {
            out.push(v("5", format!("{at}: baseline {} (only cublaslt_best is a headline)", k.baseline)));
        }
        // 6: a win or a tie needs a paired CI.
        if let Some(verdict) = &k.verdict {
            let paired = k
                .provenance
                .stats
                .as_ref()
                .is_some_and(|s| s.ci.is_some() && matches!(s.pairing, Pairing::Paired { .. }));
            if !paired {
                out.push(v("6", format!("{at}: verdict \"{verdict}\" without a paired CI")));
            }
        }
        // 2: comparisons are shown by default only from default-view rows.
        if let Some(a) = &k.provenance.aegis {
            if !a.default_view() {
                out.push(v("2", format!("{at}: from a row outside the default filters ({a:?})")));
            }
        }
        // 10: a shape routed to cuBLASLt never shows the kernel's % as the dispatch's.
        if let Some(d) = &k.dispatch {
            if d.target == "cublaslt" {
                if let (Value::Present(dp), Value::Present(kp)) = (&d.pct, &k.kernel_pct) {
                    if dp == kp {
                        out.push(v("10", format!("{at}: dispatch cuBLASLt shows the kernel's {kp}% as its own")));
                    }
                }
            }
        }
    }

    for r in &c.regressions {
        let at = format!("regression check {} {:?} (run {})", r.impl_, r.shape, r.run);
        if let Some(a) = &r.provenance.aegis {
            if r.exclusion.is_none() && !a.default_view() {
                out.push(v("2", format!("{at}: shown by default but {a:?}")));
            }
        }
        if r.status == "regression" && r.why.is_none() {
            out.push(v("6", format!("{at}: a regression without its confirmation")));
        }
        if let Some(conf) = &r.confirmation {
            let paired = conf.provenance.stats.as_ref().is_some_and(|s| s.ci.is_some());
            if !paired {
                out.push(v("6", format!("{at}: confirmation without a CI")));
            }
        }
    }

    for d in &c.derived {
        let at = format!("derived {} of {}", d.name, d.of);
        if d.name.starts_with("latency") {
            // 11: latency carries its clock and lock state.
            let ck = &d.provenance.clocks;
            if ck.sm_mhz.is_none() || ck.control == ClockControl::Unknown {
                out.push(v("11", format!("{at}: latency without its clock and lock state")));
            }
            continue;
        }
        // 3: derived at view time from a roof, which it names.
        let Some(roof) = &d.provenance.roof else {
            out.push(v("3", format!("{at}: no roof recorded")));
            continue;
        };
        // 4: decode shapes use the read roof, others the copy roof (memory metrics).
        if let Some((m, _, _)) = d.shape {
            if roof.kind != "compute" {
                let want = if m <= DECODE_MAX_M { "read" } else { "copy" };
                if roof.kind != want {
                    out.push(v("4", format!("{at}: M = {m} held to the {} roof, not {want}", roof.kind)));
                }
            }
        }
        match &roof.origin {
            // 7: only valid microbench rows feed the hardware model.
            RoofOrigin::Measured { microbench_status, .. } if microbench_status != "valid" => {
                out.push(v("7", format!("{at}: roof from a {microbench_status} microbench row")))
            }
            // 9: a datasheet figure is labelled, never passed off as measured.
            RoofOrigin::Datasheet { label } if !label.contains("datasheet-derived") => {
                out.push(v("9", format!("{at}: datasheet roof not labelled \"datasheet-derived\"")))
            }
            _ => {}
        }
    }

    // 8: telemetry and profiled metrics are never mixed.
    for k in &c.counters {
        let s = k.provenance.source;
        if s.is_telemetry() && k.launch.is_some() {
            out.push(v("8", format!("counter {}: {s:?} telemetry attached to a profiled launch", k.metric)));
        }
        if s == Source::Ncu && k.launch.is_none() {
            out.push(v("8", format!("counter {}: a profiled metric without its launch", k.metric)));
        }
        // 9: a value for a field the device does not report can only be made up.
        if s.is_telemetry() && k.quantity.value.present().is_some() {
            let dev = k.device.as_deref().and_then(|d| c.devices.iter().find(|x| x.id == d));
            if dev.and_then(|d| d.capability(&k.metric)).is_some_and(|cap| cap.support == crate::model::Support::NotSupported) {
                out.push(v("9", format!("counter {}: a value for a field device {} does not report", k.metric, k.device.as_deref().unwrap_or("?"))));
            }
        }
    }
    out
}
