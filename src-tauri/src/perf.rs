//! AEGIS Custos perf commands: thin wrappers over `custos-perf`, which reads
//! the AEGIS Core perf DB read-only through aegis-perf. Each call opens its own
//! read-only connection (a running tune or sweep is never blocked) and runs
//! off the main thread. All logic and tests live in custos-perf.
use custos_perf::{device, kernel, measure, Connection, Filter, Sources};
use serde::Serialize;
use tauri::State;

pub struct PerfState(pub Sources);

impl PerfState {
    /// `AEGIS_CORE` / `AEGIS_PERFDB`; without them, the repo fixtures (tests/fixtures/).
    pub fn from_env() -> Self {
        PerfState(Sources::from_env())
    }
}

async fn run<T, F>(state: &State<'_, PerfState>, f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&Sources, &Connection) -> anyhow::Result<T> + Send + 'static,
{
    let src = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let con = src.open()?;
        f(&src, &con)
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| format!("{e:#}"))
}

#[derive(Serialize)]
pub struct PerfSources {
    pub db: String,
    pub core: String,
    /// Archs with a measured arch file in Core.
    pub measured_archs: Vec<i64>,
}

#[tauri::command]
pub fn perf_sources(state: State<'_, PerfState>) -> PerfSources {
    PerfSources {
        db: state.0.db.display().to_string(),
        core: state.0.root.display().to_string(),
        measured_archs: custos_perf::measured_archs(&state.0),
    }
}

#[tauri::command]
pub async fn devices(state: State<'_, PerfState>) -> Result<Vec<device::Device>, String> {
    run(&state, custos_perf::devices).await
}

#[tauri::command]
pub async fn arch_model(state: State<'_, PerfState>, sm: i64) -> Result<Option<device::ArchModel>, String> {
    run(&state, move |s, c| custos_perf::arch_model(s, c, sm)).await
}

#[tauri::command]
pub async fn winners(state: State<'_, PerfState>, sm: i64) -> Result<Vec<custos_perf::winners::Winner>, String> {
    run(&state, move |s, c| custos_perf::winners(s, c, sm)).await
}

#[tauri::command]
pub async fn measurements(state: State<'_, PerfState>, filter: Option<Filter>) -> Result<Vec<measure::Measurement>, String> {
    let filter = filter.unwrap_or_default();
    run(&state, move |s, c| custos_perf::measurements(s, c, &filter)).await
}

#[tauri::command]
pub async fn kernel_detail(state: State<'_, PerfState>, kernel_id: String) -> Result<Option<kernel::KernelDetail>, String> {
    run(&state, move |s, c| custos_perf::kernel_detail(s, c, &kernel_id)).await
}

#[tauri::command]
pub async fn roofline(state: State<'_, PerfState>, sm: i64) -> Result<Option<custos_perf::roofline::Roofline>, String> {
    run(&state, move |s, c| custos_perf::roofline(s, c, sm)).await
}

#[tauri::command]
pub async fn compare(
    state: State<'_, PerfState>,
    sha_a: String,
    sha_b: String,
    filter: Option<Filter>,
) -> Result<measure::Compare, String> {
    let filter = filter.unwrap_or_default();
    run(&state, move |_, c| custos_perf::compare(c, &sha_a, &sha_b, &filter)).await
}

/// Startup check: can this build read the perf DB? Never fails: an
/// incompatible or missing DB is a state the UI shows.
#[tauri::command]
pub async fn perf_status(state: State<'_, PerfState>) -> Result<custos_perf::DbStatus, String> {
    let src = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || custos_perf::db_status(&src)).await.map_err(|e| e.to_string())
}
