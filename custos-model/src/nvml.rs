//! NVML live telemetry: clocks, temperature, power, energy, utilization,
//! clock event (throttle) reasons, memory (CLAUDE.md rule 8: continuous
//! telemetry, never hardware counters).
//!
//! Backends of [`crate::telemetry`]:
//! - [`NvmlLib`], the NVML library through nvml-wrapper (feature `nvml`; the
//!   library is loaded at run time, so a build needs no NVIDIA software);
//! - [`Recorded`], a recorded probe: the tests' NVML mock (hand-built,
//!   synthetic) and what `examples/nvml_probe --record` writes.
//!
//! [`Nvml`] reports the library "unavailable" with the reason when it cannot be
//! loaded or the crate was built without the feature.
use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::adapter::{Adapter, Availability};
use crate::provenance::{Known, Source};
use crate::telemetry::{Read, TelemetryBackend};

/// A recorded field read.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FieldRecord {
    Value { value: f64 },
    Error { error: String },
    /// "not_supported" (NVML_ERROR_NOT_SUPPORTED) or "not_read".
    Status(String),
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RecordedDevice {
    pub name: Option<String>,
    pub compute_capability: Option<(i64, i64)>,
    /// One read of each field ([`crate::telemetry::FIELDS`]); a missing field reads as an error.
    pub fields: BTreeMap<String, FieldRecord>,
    /// Repeated reads of a field: (ms since the first read, value), for its granularity.
    #[serde(default)]
    pub series: BTreeMap<String, Vec<(f64, f64)>>,
    /// The granularity the recording machine observed, as text (the probe's table).
    #[serde(default)]
    pub granularity: BTreeMap<String, String>,
}

/// A recorded probe (JSON). Machine details are never recorded: no UUID, serial,
/// PCI bus id or host name; devices are by index.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Recorded {
    #[serde(default)]
    pub synthetic: bool,
    #[serde(default)]
    pub note: Option<String>,
    pub nvml_version: Option<String>,
    pub driver_version: Option<String>,
    pub cuda_driver_version: Option<String>,
    pub devices: Vec<RecordedDevice>,
}

impl Recorded {
    pub fn load(path: &std::path::Path) -> Result<Recorded> {
        let s = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parse {} (a recorded NVML probe)", path.display()))
    }
}

fn opt(v: &Option<String>, what: &str) -> Read<String> {
    v.clone().map_or_else(|| Read::Err(format!("{what} not recorded")), Read::Ok)
}

impl TelemetryBackend for Recorded {
    fn source(&self) -> Source {
        Source::Nvml
    }
    fn tool(&self) -> (String, Known<String>) {
        ("NVML".into(), self.nvml_version.clone().map_or(Known::Unknown("not recorded".into()), Known::Known))
    }
    fn driver_version(&self) -> Read<String> {
        opt(&self.driver_version, "driver version")
    }
    fn cuda_driver_version(&self) -> Read<String> {
        opt(&self.cuda_driver_version, "CUDA version")
    }
    fn device_count(&self) -> Result<u32> {
        Ok(self.devices.len() as u32)
    }
    fn name(&self, i: u32) -> Read<String> {
        opt(&self.devices[i as usize].name, "name")
    }
    fn compute_capability(&self, i: u32) -> Read<(i64, i64)> {
        self.devices[i as usize].compute_capability.map_or(Read::Err("compute capability not recorded".into()), Read::Ok)
    }
    fn read(&self, i: u32, field: &str) -> Read<f64> {
        match self.devices.get(i as usize).and_then(|d| d.fields.get(field)) {
            Some(FieldRecord::Value { value }) => Read::Ok(*value),
            Some(FieldRecord::Error { error }) => Read::Err(error.clone()),
            Some(FieldRecord::Status(s)) if s == "not_supported" => Read::NotSupported,
            Some(FieldRecord::Status(s)) if s == "not_read" => Read::NotRead("not read when recorded".into()),
            Some(FieldRecord::Status(s)) => Read::Err(format!("unknown recorded status {s:?}")),
            None => Read::Err(format!("{field} not recorded")),
        }
    }
    fn synthetic(&self) -> bool {
        self.synthetic
    }
}

/// The NVML adapter: where the library is (None: the loader's search path).
#[derive(Clone, Debug, Default)]
pub struct Nvml {
    pub lib_path: Option<PathBuf>,
}

impl Adapter for Nvml {
    fn source(&self) -> Source {
        Source::Nvml
    }
    fn availability(&self) -> Availability {
        match self.open() {
            Ok(lib) => available(&lib),
            Err(e) => Availability::Unavailable { reason: format!("{e:#}") },
        }
    }
}

impl Nvml {
    /// The NVML library, initialized.
    pub fn open(&self) -> Result<NvmlLib> {
        NvmlLib::open(self.lib_path.as_deref())
    }
}

#[cfg(feature = "nvml")]
pub use real::NvmlLib;

#[cfg(feature = "nvml")]
fn available(lib: &NvmlLib) -> Availability {
    Availability::Available { tool: "NVML".into(), version: lib.tool().1 }
}

/// Without the `nvml` feature there is no library to open.
#[cfg(not(feature = "nvml"))]
pub enum NvmlLib {}

#[cfg(not(feature = "nvml"))]
fn available(lib: &NvmlLib) -> Availability {
    match *lib {}
}

#[cfg(not(feature = "nvml"))]
impl NvmlLib {
    pub fn open(_lib: Option<&std::path::Path>) -> Result<NvmlLib> {
        bail!("NVML unavailable: custos-model was built without the \"nvml\" feature")
    }
}

#[cfg(feature = "nvml")]
mod real {
    use std::path::Path;

    use anyhow::{anyhow, Result};
    use nvml_wrapper::enum_wrappers::device::{Clock, TemperatureSensor};
    use nvml_wrapper::enums::device::SampleValue;
    use nvml_wrapper::error::NvmlError;
    use nvml_wrapper::structs::device::FieldId;
    use nvml_wrapper::sys_exports::field_id::{NVML_FI_DEV_POWER_AVERAGE, NVML_FI_DEV_POWER_INSTANT};

    use crate::provenance::{Known, Source};
    use crate::telemetry::{Read, TelemetryBackend};

    pub struct NvmlLib {
        nvml: nvml_wrapper::Nvml,
    }

    fn r<T>(x: Result<T, NvmlError>) -> Read<T> {
        match x {
            Ok(v) => Read::Ok(v),
            Err(NvmlError::NotSupported) => Read::NotSupported,
            Err(e) => Read::Err(e.to_string()),
        }
    }

    impl NvmlLib {
        pub fn open(lib: Option<&Path>) -> Result<NvmlLib> {
            let mut b = nvml_wrapper::Nvml::builder();
            if let Some(p) = lib {
                b.lib_path(p.as_os_str());
            }
            let nvml = b.init().map_err(|e| match e {
                NvmlError::LibloadingError(l) => anyhow!("NVML unavailable: the NVML library (libnvidia-ml.so.1) could not be loaded ({l})"),
                NvmlError::DriverNotLoaded => anyhow!("NVML unavailable: the NVIDIA driver is not loaded"),
                NvmlError::LibraryNotFound => anyhow!("NVML unavailable: libnvidia-ml.so.1 not found"),
                other => anyhow!("NVML unavailable: init failed ({other})"),
            })?;
            Ok(NvmlLib { nvml })
        }

        fn field_value(&self, i: u32, id: u32) -> Read<f64> {
            let d = match self.nvml.device_by_index(i) {
                Ok(d) => d,
                Err(e) => return Read::Err(e.to_string()),
            };
            match d.field_values_for(&[FieldId(id)]) {
                Ok(mut v) => match v.pop() {
                    Some(Ok(s)) => match s.value {
                        Ok(SampleValue::F64(x)) => Read::Ok(x),
                        Ok(SampleValue::U32(x)) => Read::Ok(x as f64),
                        Ok(SampleValue::U64(x)) => Read::Ok(x as f64),
                        Ok(SampleValue::I64(x)) => Read::Ok(x as f64),
                        Err(e) => r(Err(e)),
                    },
                    Some(Err(e)) => r(Err(e)),
                    None => Read::Err("no field value returned".into()),
                },
                Err(e) => r(Err(e)),
            }
        }
    }

    impl TelemetryBackend for NvmlLib {
        fn source(&self) -> Source {
            Source::Nvml
        }
        fn tool(&self) -> (String, Known<String>) {
            ("NVML".into(), self.nvml.sys_nvml_version().map_or_else(|e| Known::Unknown(e.to_string()), Known::Known))
        }
        fn driver_version(&self) -> Read<String> {
            r(self.nvml.sys_driver_version())
        }
        fn cuda_driver_version(&self) -> Read<String> {
            r(self.nvml.sys_cuda_driver_version()).map(|v| format!("{}.{}", v / 1000, v % 1000 / 10))
        }
        fn device_count(&self) -> Result<u32> {
            Ok(self.nvml.device_count()?)
        }
        fn name(&self, i: u32) -> Read<String> {
            r(self.nvml.device_by_index(i).and_then(|d| d.name()))
        }
        fn compute_capability(&self, i: u32) -> Read<(i64, i64)> {
            r(self.nvml.device_by_index(i).and_then(|d| d.cuda_compute_capability())).map(|c| (c.major as i64, c.minor as i64))
        }
        fn read(&self, i: u32, field: &str) -> Read<f64> {
            let d = match self.nvml.device_by_index(i) {
                Ok(d) => d,
                Err(e) => return Read::Err(e.to_string()),
            };
            match field {
                "clocks.graphics" => r(d.clock_info(Clock::Graphics)).map(f64::from),
                "clocks.sm" => r(d.clock_info(Clock::SM)).map(f64::from),
                "clocks.memory" => r(d.clock_info(Clock::Memory)).map(f64::from),
                "temperature.gpu" => r(d.temperature(TemperatureSensor::Gpu)).map(f64::from),
                "power.usage" => r(d.power_usage()).map(f64::from),
                "power.instant" => self.field_value(i, NVML_FI_DEV_POWER_INSTANT),
                "power.average" => self.field_value(i, NVML_FI_DEV_POWER_AVERAGE),
                "power.limit" => r(d.enforced_power_limit()).map(f64::from),
                "energy.total" => r(d.total_energy_consumption()).map(|e| e as f64),
                "utilization.gpu" => r(d.utilization_rates()).map(|u| f64::from(u.gpu)),
                "utilization.memory" => r(d.utilization_rates()).map(|u| f64::from(u.memory)),
                "clocks_event_reasons" => r(d.current_throttle_reasons()).map(|t| t.bits() as f64),
                "memory.used" => r(d.memory_info()).map(|m| m.used as f64),
                "memory.total" => r(d.memory_info()).map(|m| m.total as f64),
                other => Read::NotRead(format!("{other}: not an NVML field Custos reads")),
            }
        }
    }
}

/// Sanity check of a recorded probe: every device lists every field.
pub fn check_recorded(r: &Recorded) -> Result<()> {
    for (i, d) in r.devices.iter().enumerate() {
        for f in crate::telemetry::FIELDS {
            if !d.fields.contains_key(f.field) {
                bail!("recorded device {i} has no record of {}", f.field);
            }
        }
    }
    Ok(())
}
