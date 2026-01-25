#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod monitoring;
mod threat_detection;
mod sensors;
mod storage;

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
        Ok(info) => {
            println!("System info retrieved successfully");
            Ok(info)
        }
        Err(e) => {
            println!("ERROR getting system info: {}", e);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
async fn start_monitoring(state: State<'_, ServiceState>, app: tauri::AppHandle) -> Result<(), String> {
    println!("=== start_monitoring called ===");
    let mut service = state.write().await;
    
    // Clone app handle for the callback
    let app_handle = app.clone();
    println!("App handle cloned for metrics callback");
    
    // Set up the standard metrics callback to emit events to the frontend
    service.set_metrics_callback(move |metrics| {
        println!("Emitting system-metrics event with {} processes", metrics.top_processes.len());
        let result = app_handle.emit("system-metrics", &metrics);
        if let Err(e) = result {
            println!("Error emitting system-metrics event: {}", e);
        }
    }).await;
    
    // Set up high-performance metrics callback
    let app_handle_high_perf = app.clone();
    service.set_high_perf_callback(move |metrics| {
        // Use binary serialization for high-performance metrics
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let result = app_handle_high_perf.emit("high-perf-metrics", &encoded);
            if let Err(e) = result {
                println!("Error emitting high-perf-metrics event: {}", e);
            }
        }
    }).await;
    
    // Set up kernel-level metrics callback
    let app_handle_kernel = app.clone();
    service.set_kernel_callback(move |metrics| {
        // Use binary serialization for kernel metrics
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let result = app_handle_kernel.emit("kernel-metrics", &encoded);
            if let Err(e) = result {
                println!("Error emitting kernel-metrics event: {}", e);
            }
        }
    }).await;
    
    println!("Starting monitoring service...");
    service.start_monitoring().await;
    
    // Start high-performance monitoring
    service.start_high_perf_monitoring();
    println!("High-performance monitoring started");
    
    // Start kernel-level monitoring
    match service.start_kernel_monitoring() {
        Ok(()) => println!("Kernel-level monitoring started"),
        Err(e) => println!("Warning: Failed to start kernel monitoring: {}", e),
    }
    
    println!("Monitoring service started successfully");
    Ok(())
}

#[tauri::command]
async fn start_high_perf_monitoring(state: State<'_, ServiceState>, app: tauri::AppHandle) -> Result<(), String> {
    println!("=== start_high_perf_monitoring called ===");
    let mut service = state.write().await;
    
    // Set up high-performance metrics callback with binary serialization
    let app_handle = app.clone();
    service.set_high_perf_callback(move |metrics| {
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let result = app_handle.emit("high-perf-metrics", &encoded);
            if let Err(e) = result {
                println!("Error emitting high-perf-metrics event: {}", e);
            }
        }
    }).await;
    
    service.start_high_perf_monitoring();
    println!("High-performance monitoring started successfully");
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
    match service.collect_metrics().await {
        Ok(metrics) => {
            Ok(metrics)
        }
        Err(e) => {
            println!("ERROR collecting current metrics: {}", e);
            Err(e)
        }
    }
}

#[tauri::command]
async fn get_high_perf_metrics(state: State<'_, ServiceState>) -> Result<Option<HighPerfMetrics>, String> {
    println!("=== get_high_perf_metrics called ===");
    let service = state.read().await;
    let metrics = service.get_high_perf_metrics();
    println!("High-performance metrics retrieved: {}", metrics.is_some());
    Ok(metrics)
}

#[tauri::command]
async fn start_kernel_monitoring(state: State<'_, ServiceState>, app: tauri::AppHandle) -> Result<(), String> {
    println!("=== start_kernel_monitoring called ===");
    let mut service = state.write().await;
    
    // Set up kernel metrics callback with binary serialization
    let app_handle = app.clone();
    service.set_kernel_callback(move |metrics| {
        if let Ok(encoded) = bincode::serialize(&metrics) {
            let result = app_handle.emit("kernel-metrics", &encoded);
            if let Err(e) = result {
                println!("Error emitting kernel-metrics event: {}", e);
            }
        }
    }).await;
    
    match service.start_kernel_monitoring() {
        Ok(()) => {
            println!("Kernel-level monitoring started successfully");
            Ok(())
        }
        Err(e) => {
            println!("Failed to start kernel monitoring: {}", e);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
async fn stop_kernel_monitoring(state: State<'_, ServiceState>) -> Result<(), String> {
    println!("=== stop_kernel_monitoring called ===");
    let mut service = state.write().await;
    service.stop_kernel_monitoring();
    println!("Kernel-level monitoring stopped");
    Ok(())
}

#[tauri::command]
async fn get_kernel_metrics(state: State<'_, ServiceState>) -> Result<Option<KernelMetrics>, String> {
    println!("=== get_kernel_metrics called ===");
    let service = state.read().await;
    let metrics = service.get_kernel_metrics();
    println!("Kernel metrics retrieved: {}", metrics.is_some());
    Ok(metrics)
}

#[tauri::command]
async fn get_pci_devices() -> Result<Vec<PciDevice>, String> {
    println!("=== get_pci_devices called ===");
    match PciEnumerator::enumerate_devices() {
        Ok(devices) => {
            println!("Found {} PCI devices", devices.len());
            Ok(devices)
        }
        Err(e) => {
            println!("Failed to enumerate PCI devices: {}", e);
            Err(e.to_string())
        }
    }
}

#[tauri::command]
async fn get_platform_security() -> Result<PlatformSecurityStatus, String> {
    println!("=== get_platform_security called ===");
    match PlatformSecurityMonitor::get_security_status() {
        Ok(status) => {
            println!("Platform security status retrieved");
            println!("  TPM Present: {}", status.tpm.present);
            println!("  Secure Boot: {}", status.secure_boot.enabled);
            println!("  Firmware: {}", status.firmware.firmware_type);
            Ok(status)
        }
        Err(e) => {
            println!("Failed to get platform security status: {}", e);
            Err(e.to_string())
        }
    }
}

// Threat Detection Commands

#[tauri::command]
async fn get_threat_statistics(state: State<'_, ThreatDetectionState>) -> Result<ThreatStats, String> {
    println!("=== get_threat_statistics called ===");
    Ok(state.get_statistics())
}

#[tauri::command]
async fn get_recent_threats(state: State<'_, ThreatDetectionState>, limit: usize) -> Result<Vec<ThreatEvent>, String> {
    println!("=== get_recent_threats called with limit {} ===", limit);
    Ok(state.get_recent_threats(limit))
}

#[tauri::command]
async fn get_all_alerts(state: State<'_, ThreatDetectionState>) -> Result<Vec<Alert>, String> {
    println!("=== get_all_alerts called ===");
    let alert_manager = state.get_alert_manager();
    Ok(alert_manager.get_alerts())
}

#[tauri::command]
async fn get_unacknowledged_alerts(state: State<'_, ThreatDetectionState>) -> Result<Vec<Alert>, String> {
    println!("=== get_unacknowledged_alerts called ===");
    let alert_manager = state.get_alert_manager();
    Ok(alert_manager.get_unacknowledged_alerts())
}

#[tauri::command]
async fn acknowledge_alert(
    state: State<'_, ThreatDetectionState>,
    alert_id: String,
    user: String,
) -> Result<bool, String> {
    println!("=== acknowledge_alert called for {} ===", alert_id);
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
    println!("=== add_alert_note called for {} ===", alert_id);
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
    println!("=== scan_process_for_threats called for {} ===", process_name);
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

fn main() {
    println!("=== Starting Custos Security Application ===");

    // Initialize the monitoring service with high-performance capabilities
    println!("Initializing high-performance monitoring service...");
    let service = Arc::new(RwLock::new(MonitoringService::new_with_high_perf(3000))); // 3000ms update interval (3 seconds)
    println!("High-performance monitoring service initialized successfully");

    // Initialize threat detection engine
    println!("Initializing threat detection engine...");
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

    // API keys can be loaded from environment or config file
    let claude_api_key = std::env::var("CLAUDE_API_KEY").ok();
    let threat_intel_keys = ThreatIntelApiKeys {
        virustotal_api_key: std::env::var("VIRUSTOTAL_API_KEY").ok(),
        abuseipdb_api_key: std::env::var("ABUSEIPDB_API_KEY").ok(),
        alienvault_api_key: std::env::var("ALIENVAULT_API_KEY").ok(),
    };

    let threat_engine = Arc::new(ThreatDetectionEngine::new(
        threat_config,
        claude_api_key,
        threat_intel_keys,
    ));
    println!("Threat detection engine initialized successfully");

    tauri::Builder::default()
        .manage(service)
        .manage(threat_engine)
        .setup(|app| {
            println!("=== Tauri App Setup ===");
            println!("App is initializing...");
            
            #[cfg(debug_assertions)]
            {
                if let Some(window) = app.get_webview_window("main") {
                    println!("Opening devtools for main window");
                    window.open_devtools();
                    
                    // Log window properties
                    if let Ok(pos) = window.outer_position() {
                        println!("Window position: {:?}", pos);
                    }
                    if let Ok(size) = window.outer_size() {
                        println!("Window size: {:?}", size);
                    }
                } else {
                    println!("WARNING: Main window not found!");
                }
            }
            
            println!("Tauri setup complete");
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
            scan_process_for_threats
        ])
        .on_window_event(|window, event| {
            match event {
                tauri::WindowEvent::Focused(focused) => {
                    println!("Window {} focused: {}", window.label(), focused);
                }
                tauri::WindowEvent::Resized(size) => {
                    println!("Window {} resized to: {:?}", window.label(), size);
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}