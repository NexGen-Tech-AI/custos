//! Custos library for integration tests

// The system monitor's collectors keep unused items (speculative probes,
// platform-only paths, stubs): kept, not pruned (CLAUDE.md, "Legacy code").
#[allow(dead_code)]
pub mod monitoring;
