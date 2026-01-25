#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod monitoring;

use std::sync::Arc;
use tauri::{Manager, State, Emitter};
use tokio::sync::RwLock;
use monitoring::{MonitoringService, SystemInfo, SystemMetrics};
use monitoring::high_perf_monitor::HighPerfMetrics;
use monitoring::kernel_monitor::KernelMetrics;
use monitoring::{PciDevice, PciEnumerator};
use monitoring::{PlatformSecurityStatus, PlatformSecurityMonitor};

type ServiceState = Arc<RwLock<MonitoringService>>;

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

fn main() {
    println!("=== Starting System Monitor Tauri Application ===");
    
    // Initialize the monitoring service with high-performance capabilities
    println!("Initializing high-performance monitoring service...");
    let service = Arc::new(RwLock::new(MonitoringService::new_with_high_perf(3000))); // 3000ms update interval (3 seconds)
    println!("High-performance monitoring service initialized successfully");
    
    tauri::Builder::default()
        .manage(service)
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
            get_platform_security
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