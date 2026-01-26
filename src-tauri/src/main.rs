#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod monitoring;
mod threat_detection;
mod sensors;
mod storage;
mod keychain;

use std::sync::Arc;
use tauri::{Manager, State, Emitter};
use tokio::sync::RwLock;
use monitoring::{MonitoringService, SystemInfo, SystemMetrics};
use monitoring::high_perf_monitor::HighPerfMetrics;
use monitoring::kernel_monitor::KernelMetrics;
use monitoring::{PciDevice, PciEnumerator};
use monitoring::{PlatformSecurityStatus, PlatformSecurityMonitor};

use threat_detection::engine::ThreatDetectionEngine;
use threat_detection::{ThreatDetectionConfig, ThreatEvent};
use threat_detection::threat_intel::ThreatIntelApiKeys;
use threat_detection::alerts::Alert;
use threat_detection::engine::ThreatStats;

type ServiceState = Arc<RwLock<MonitoringService>>;
type ThreatDetectionState = Arc<ThreatDetectionEngine>;

#[tauri::command]
async fn get_system_info(state: State<'_, ServiceState>) -> Result<SystemInfo, String> {
    
    let service = state.read().await;
    match service.get_system_info().await {
        Ok(info) => Ok(info),
        Err(e) => Err(e.to_string())
    }
}

#[tauri::command]
async fn start_monitoring(state: State<'_, ServiceState>, app: tauri::AppHandle) -> Result<(), String> {
    let mut service = state.write().await;

    // Clone app handle for the callback
    let app_handle = app.clone();

    // Set up the standard metrics callback to emit events to the frontend
    service.set_metrics_callback(move |metrics| {
        let _ = app_handle.emit("system-metrics", &metrics);
    }).await;
    
    // Set up high-performance metrics callback
    let app_handle_high_perf = app.clone();
    service.set_high_perf_callback(move |metrics| {
        // Use binary serialization for high-performance metrics
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let _ = app_handle_high_perf.emit("high-perf-metrics", &encoded);
        }
    }).await;
    
    // Set up kernel-level metrics callback
    let app_handle_kernel = app.clone();
    service.set_kernel_callback(move |metrics| {
        // Use binary serialization for kernel metrics
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let _ = app_handle_kernel.emit("kernel-metrics", &encoded);
        }
    }).await;

    service.start_monitoring().await;
    service.start_high_perf_monitoring();
    let _ = service.start_kernel_monitoring();

    Ok(())
}

#[tauri::command]
async fn start_high_perf_monitoring(state: State<'_, ServiceState>, app: tauri::AppHandle) -> Result<(), String> {
    let mut service = state.write().await;

    // Set up high-performance metrics callback with binary serialization
    let app_handle = app.clone();
    service.set_high_perf_callback(move |metrics| {
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let _ = app_handle.emit("high-perf-metrics", &encoded);
        }
    }).await;

    service.start_high_perf_monitoring();
    Ok(())
}

#[tauri::command]
async fn stop_monitoring(_state: State<'_, ServiceState>) -> Result<(), String> {
    // In this simple version, we don't stop the monitoring
    Ok(())
}

#[tauri::command]
async fn get_current_metrics(state: State<'_, ServiceState>) -> Result<SystemMetrics, String> {
    let service = state.read().await;
    service.collect_metrics().await.map_err(|e| e)
}

#[tauri::command]
async fn get_high_perf_metrics(state: State<'_, ServiceState>) -> Result<Option<HighPerfMetrics>, String> {
    let service = state.read().await;
    Ok(service.get_high_perf_metrics())
}

#[tauri::command]
async fn start_kernel_monitoring(state: State<'_, ServiceState>, app: tauri::AppHandle) -> Result<(), String> {
    let mut service = state.write().await;

    // Set up kernel metrics callback with binary serialization
    let app_handle = app.clone();
    service.set_kernel_callback(move |metrics| {
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let _ = app_handle.emit("kernel-metrics", &encoded);
        }
    }).await;

    service.start_kernel_monitoring().map_err(|e| e.to_string())
}

#[tauri::command]
async fn stop_kernel_monitoring(state: State<'_, ServiceState>) -> Result<(), String> {
    let mut service = state.write().await;
    service.stop_kernel_monitoring();
    Ok(())
}

#[tauri::command]
async fn get_kernel_metrics(state: State<'_, ServiceState>) -> Result<Option<KernelMetrics>, String> {
    let service = state.read().await;
    Ok(service.get_kernel_metrics())
}

#[tauri::command]
async fn get_pci_devices() -> Result<Vec<PciDevice>, String> {
    PciEnumerator::enumerate_devices().map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_platform_security() -> Result<PlatformSecurityStatus, String> {
    PlatformSecurityMonitor::get_security_status().map_err(|e| e.to_string())
}

// Threat Detection Commands

#[tauri::command]
async fn get_threat_statistics(state: State<'_, ThreatDetectionState>) -> Result<ThreatStats, String> {
    Ok(state.get_statistics())
}

#[tauri::command]
async fn get_recent_threats(state: State<'_, ThreatDetectionState>, limit: usize) -> Result<Vec<ThreatEvent>, String> {
    Ok(state.get_recent_threats(limit))
}

#[tauri::command]
async fn get_all_alerts(state: State<'_, ThreatDetectionState>) -> Result<Vec<Alert>, String> {
    let alert_manager = state.get_alert_manager();
    Ok(alert_manager.get_alerts())
}

#[tauri::command]
async fn get_unacknowledged_alerts(state: State<'_, ThreatDetectionState>) -> Result<Vec<Alert>, String> {
    let alert_manager = state.get_alert_manager();
    Ok(alert_manager.get_unacknowledged_alerts())
}

#[tauri::command]
async fn acknowledge_alert(
    state: State<'_, ThreatDetectionState>,
    alert_id: String,
    user: String,
) -> Result<bool, String> {
    let alert_manager = state.get_alert_manager();
    Ok(alert_manager.acknowledge_alert(&alert_id, &user))
}

#[tauri::command]
async fn add_alert_note(
    state: State<'_, ThreatDetectionState>,
    alert_id: String,
    note: String,
    author: String,
) -> Result<(), String> {
    let alert_manager = state.get_alert_manager();
    alert_manager.add_note(&alert_id, note, &author);
    Ok(())
}

#[tauri::command]
async fn scan_process_for_threats(
    state: State<'_, ThreatDetectionState>,
    process_name: String,
    process_path: String,
    process_id: u32,
    parent_process: Option<String>,
    command_line: Option<String>,
    cpu_usage: f64,
    memory_usage: u64,
    network_connections: usize,
    file_operations: u64,
) -> Result<Vec<ThreatEvent>, String> {
    Ok(state.scan_process(
        &process_name,
        &process_path,
        process_id,
        parent_process.as_deref(),
        command_line.as_deref(),
        cpu_usage,
        memory_usage,
        network_connections,
        file_operations,
    ).await)
}

// API Key Management Commands

#[tauri::command]
async fn set_api_key(
    key_type: String,
    api_key: String,
) -> Result<(), String> {
    use keychain::{KeychainManager, ApiKeyType};

    let key_type_enum = match key_type.as_str() {
        "claude" => ApiKeyType::Claude,
        "virustotal" => ApiKeyType::VirusTotal,
        "abuseipdb" => ApiKeyType::AbuseIPDB,
        "alienvault" => ApiKeyType::AlienVault,
        _ => return Err(format!("Unknown API key type: {}", key_type)),
    };

    KeychainManager::set_api_key(key_type_enum, &api_key)
        .map_err(|e| format!("Failed to store API key: {}", e))
}

#[tauri::command]
async fn get_api_key(
    key_type: String,
) -> Result<Option<String>, String> {
    use keychain::{KeychainManager, ApiKeyType};

    let key_type_enum = match key_type.as_str() {
        "claude" => ApiKeyType::Claude,
        "virustotal" => ApiKeyType::VirusTotal,
        "abuseipdb" => ApiKeyType::AbuseIPDB,
        "alienvault" => ApiKeyType::AlienVault,
        _ => return Err(format!("Unknown API key type: {}", key_type)),
    };

    KeychainManager::get_api_key(key_type_enum)
        .map_err(|e| format!("Failed to retrieve API key: {}", e))
}

#[tauri::command]
async fn delete_api_key(
    key_type: String,
) -> Result<(), String> {
    use keychain::{KeychainManager, ApiKeyType};

    let key_type_enum = match key_type.as_str() {
        "claude" => ApiKeyType::Claude,
        "virustotal" => ApiKeyType::VirusTotal,
        "abuseipdb" => ApiKeyType::AbuseIPDB,
        "alienvault" => ApiKeyType::AlienVault,
        _ => return Err(format!("Unknown API key type: {}", key_type)),
    };

    KeychainManager::delete_api_key(key_type_enum)
        .map_err(|e| format!("Failed to delete API key: {}", e))
}

#[tauri::command]
async fn has_api_key(
    key_type: String,
) -> Result<bool, String> {
    use keychain::{KeychainManager, ApiKeyType};

    let key_type_enum = match key_type.as_str() {
        "claude" => ApiKeyType::Claude,
        "virustotal" => ApiKeyType::VirusTotal,
        "abuseipdb" => ApiKeyType::AbuseIPDB,
        "alienvault" => ApiKeyType::AlienVault,
        _ => return Err(format!("Unknown API key type: {}", key_type)),
    };

    Ok(KeychainManager::has_api_key(key_type_enum))
}

#[tauri::command]
async fn get_configured_api_keys() -> Result<Vec<String>, String> {
    use keychain::KeychainManager;

    let configured = KeychainManager::get_configured_keys();
    let key_names: Vec<String> = configured
        .iter()
        .map(|k| format!("{:?}", k).to_lowercase())
        .collect();

    Ok(key_names)
}

fn main() {
    // Initialize the monitoring service with high-performance capabilities
    let service = Arc::new(RwLock::new(MonitoringService::new_with_high_perf(3000))); // 3000ms update interval (3 seconds)

    // Initialize threat detection engine
    let threat_config = ThreatDetectionConfig {
        enabled: true,
        behavioral_detection: true,
        signature_detection: true,
        ai_analysis: false, // Disabled by default, can be enabled with API key
        threat_intel: false, // Disabled by default, can be enabled with API keys
        min_severity_to_alert: threat_detection::ThreatSeverity::Medium,
        auto_remediate: false, // Disabled by default for safety
        learning_mode: true,
        scan_interval_ms: 5000,
    };

    // API keys loaded from OS keychain with environment variable fallback
    use keychain::{KeychainManager, ApiKeyType};

    let claude_api_key = KeychainManager::load_api_key_with_fallback(
        ApiKeyType::Claude,
        "CLAUDE_API_KEY"
    );
    let threat_intel_keys = ThreatIntelApiKeys {
        virustotal_api_key: KeychainManager::load_api_key_with_fallback(
            ApiKeyType::VirusTotal,
            "VIRUSTOTAL_API_KEY"
        ),
        abuseipdb_api_key: KeychainManager::load_api_key_with_fallback(
            ApiKeyType::AbuseIPDB,
            "ABUSEIPDB_API_KEY"
        ),
        alienvault_api_key: KeychainManager::load_api_key_with_fallback(
            ApiKeyType::AlienVault,
            "ALIENVAULT_API_KEY"
        ),
    };

    let threat_engine = Arc::new(ThreatDetectionEngine::new(
        threat_config,
        claude_api_key,
        threat_intel_keys,
    ));

    tauri::Builder::default()
        .manage(service)
        .manage(threat_engine)
        .setup(|app| {
            #[cfg(debug_assertions)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_system_info,
            start_monitoring,
            start_high_perf_monitoring,
            stop_monitoring,
            get_current_metrics,
            get_high_perf_metrics,
            start_kernel_monitoring,
            stop_kernel_monitoring,
            get_kernel_metrics,
            get_pci_devices,
            get_platform_security,
            // Threat Detection
            get_threat_statistics,
            get_recent_threats,
            get_all_alerts,
            get_unacknowledged_alerts,
            acknowledge_alert,
            add_alert_note,
            scan_process_for_threats,
            // API Key Management
            set_api_key,
            get_api_key,
            delete_api_key,
            has_api_key,
            get_configured_api_keys
        ])
        .on_window_event(|_window, _event| {})
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}