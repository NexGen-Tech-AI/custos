//! AEGIS Custos's internal model and its NVIDIA-tool adapters.
//!
//! Custos builds on NVIDIA's tools instead of collecting data itself: Nsight
//! Systems timelines, Nsight Compute metrics, NVML telemetry, SASS listings,
//! and AEGIS Core's perf DB (custos-perf, behind the `aegis` feature) all
//! become one [`model::Capture`], every value with its [`provenance::Provenance`],
//! checked against the data contract ([`contract`]).
pub mod adapter;
pub mod contract;
pub mod model;
pub mod ncu;
pub mod nsys;
pub mod provenance;
pub mod sidecar;

pub use model::Capture;
pub use provenance::Provenance;
