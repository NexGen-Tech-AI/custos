#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod monitoring;
mod threat_detection;
mod sensors;
mod storage;
mod keychain;
mod network;
mod vulnerability;
mod ai_analysis;
mod hardware_detector;
mod ollama;
mod malware;

use std::sync::Arc;
use tauri::{Manager, State, Emitter};
use tokio::sync::RwLock;
use parking_lot::Mutex;
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

// ========================================
// Scan Progress State
// ========================================

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub status: ScanStatus,
    pub scan_type: ScanType,
    pub packages_scanned: usize,
    pub total_packages: usize,
    pub vulnerabilities_found: usize,
    pub critical_threats: usize,
    pub elapsed_seconds: u64,
    pub current_package: Option<String>,
    pub eta_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Idle,
    Scanning,
    Complete,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    Quick,
    Full,
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self {
            status: ScanStatus::Idle,
            scan_type: ScanType::Quick,
            packages_scanned: 0,
            total_packages: 0,
            vulnerabilities_found: 0,
            critical_threats: 0,
            elapsed_seconds: 0,
            current_package: None,
            eta_seconds: None,
        }
    }
}

type ScanProgressState = Arc<Mutex<ScanProgress>>;
type ComprehensiveScannerState = Arc<Mutex<Option<ComprehensiveScanner>>>;

// Cached vulnerability findings from last scan
type VulnerabilityFindingsCache = Arc<Mutex<Vec<VulnerabilityFinding>>>;

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

// ========================================
// Network Security Commands
// ========================================

use network::{
    NetworkConnectionRecord, ConnectionHistoryManager, TopTalker, ConnectionStats,
    DNSAnalyzer, DNSQuery,
    NetworkSegmentationEngine, NetworkSegment, SegmentPolicy, SegmentConfig,
    GeoIPLookup, GeoIPInfo,
    IsolationManager, IsolationAction, ActionPreview, ActionResult, IsolationRecord,
};

#[tauri::command]
async fn get_network_connections(
    hours: u64,
    limit: usize,
) -> Result<Vec<NetworkConnectionRecord>, String> {
    let db_path = "data/events.db";
    let db = storage::EventDatabase::new(db_path).map_err(|e| e.to_string())?;
    let manager = ConnectionHistoryManager::new(db);
    manager.get_recent_connections(hours, limit)
}

#[tauri::command]
async fn get_top_talkers(limit: usize, hours: u64) -> Result<Vec<TopTalker>, String> {
    let db_path = "data/events.db";
    let db = storage::EventDatabase::new(db_path).map_err(|e| e.to_string())?;
    let manager = ConnectionHistoryManager::new(db);
    manager.get_top_talkers(limit, hours)
}

#[tauri::command]
async fn get_connection_stats(hours: u64) -> Result<ConnectionStats, String> {
    let db_path = "data/events.db";
    let db = storage::EventDatabase::new(db_path).map_err(|e| e.to_string())?;
    let manager = ConnectionHistoryManager::new(db);
    manager.get_stats(hours)
}

#[tauri::command]
async fn analyze_dns_query(query: String, process_name: String) -> Result<(bool, Vec<String>), String> {
    let analyzer = DNSAnalyzer::new();
    Ok(analyzer.analyze(&query, &process_name))
}

#[tauri::command]
async fn classify_ip(ip: String) -> Result<NetworkSegment, String> {
    let engine = NetworkSegmentationEngine::new();
    Ok(engine.classify_ip(&ip))
}

#[tauri::command]
async fn get_segment_policies() -> Result<Vec<SegmentPolicy>, String> {
    let engine = NetworkSegmentationEngine::new();
    Ok(engine.get_policies().to_vec())
}

#[tauri::command]
async fn update_segment_policy(policy: SegmentPolicy) -> Result<(), String> {
    // In production, persist this to config file/database
    println!("Updating segment policy: {:?}", policy.segment);
    Ok(())
}

#[tauri::command]
async fn lookup_ip_info(ip: String) -> Result<GeoIPInfo, String> {
    let geoip = GeoIPLookup::new();
    geoip.lookup(&ip)
}

#[tauri::command]
async fn preview_isolation_action(action: IsolationAction) -> Result<ActionPreview, String> {
    let manager = IsolationManager::new();
    Ok(manager.preview_action(&action))
}

#[tauri::command]
async fn execute_isolation_action(
    action: IsolationAction,
    user: String,
) -> Result<ActionResult, String> {
    let mut manager = IsolationManager::new();
    manager.execute_action(action, user)
}

#[tauri::command]
async fn rollback_isolation(action_id: String) -> Result<(), String> {
    let mut manager = IsolationManager::new();
    manager.rollback_action(&action_id)
}

#[tauri::command]
async fn get_isolation_history() -> Result<Vec<IsolationRecord>, String> {
    let manager = IsolationManager::new();
    Ok(manager.get_history())
}

// ========================================
// Vulnerability Scanning Commands
// ========================================

use vulnerability::{
    VulnerabilityScanner, VulnerabilityFinding, ScanStatistics,
    CVE, CVESeverity,
    VulnerabilityPrioritizer, PrioritizedFinding, PackageVulnerabilityGroup,
    MisconfigurationScanner, Misconfiguration, MisconfigSeverity,
    FindingStatus,
    ComprehensiveScanner, ComprehensiveScanProgress, ThreatFinding,
    ThreatType, ThreatSeverity, ScanPhase,
};
use sensors::PackageSensor;

/// Get current scan progress (polled by UI)
#[tauri::command]
async fn get_scan_progress(scan_state: State<'_, ScanProgressState>) -> Result<ScanProgress, String> {
    let progress = scan_state.lock().clone();
    Ok(progress)
}

/// Start a quick scan (critical packages only)
#[tauri::command]
async fn start_quick_scan(
    scan_state: State<'_, ScanProgressState>,
    findings_cache: State<'_, VulnerabilityFindingsCache>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    println!("=== QUICK SCAN STARTED ===");

    // Initialize scan progress
    {
        let mut progress = scan_state.lock();
        *progress = ScanProgress {
            status: ScanStatus::Scanning,
            scan_type: ScanType::Quick,
            packages_scanned: 0,
            total_packages: 0,
            vulnerabilities_found: 0,
            critical_threats: 0,
            elapsed_seconds: 0,
            current_package: None,
            eta_seconds: None,
        };
    }

    // Clone state for background task
    let scan_state_clone = Arc::clone(&scan_state.inner());
    let findings_cache_clone = Arc::clone(&findings_cache.inner());

    // Run scan in background
    tokio::spawn(async move {
        let start_time = std::time::Instant::now();

        // Get package sensor
        #[cfg(target_os = "linux")]
        let sensor = match PackageSensor::new_linux() {
            Ok(s) => s,
            Err(e) => {
                println!("ERROR: Failed to create package sensor: {}", e);
                let mut progress = scan_state_clone.lock();
                progress.status = ScanStatus::Error;
                return;
            }
        };

        #[cfg(target_os = "windows")]
        let sensor = match PackageSensor::new_windows() {
            Ok(s) => s,
            Err(e) => {
                println!("ERROR: Failed to create package sensor: {}", e);
                let mut progress = scan_state_clone.lock();
                progress.status = ScanStatus::Error;
                return;
            }
        };

        #[cfg(target_os = "macos")]
        let sensor = match PackageSensor::new_macos() {
            Ok(s) => s,
            Err(e) => {
                println!("ERROR: Failed to create package sensor: {}", e);
                let mut progress = scan_state_clone.lock();
                progress.status = ScanStatus::Error;
                return;
            }
        };

        println!("Getting installed packages inventory...");
        let all_packages = sensor.get_inventory();

        // Quick scan - filter to critical packages only
        let critical_package_names = vec![
            "openssl", "libssl", "openssl-libs",
            "sudo", "linux-kernel", "linux", "kernel",
            "curl", "libcurl", "wget",
            "bash", "zsh", "ssh", "openssh", "openssh-server", "openssh-client",
            "systemd", "glibc", "libc6",
            "apache2", "nginx", "httpd",
            "docker", "containerd", "runc",
            "python3", "nodejs", "java",
        ];

        let packages: Vec<_> = all_packages.into_iter()
            .filter(|pkg| {
                critical_package_names.iter().any(|&name|
                    pkg.name.to_lowercase().contains(name)
                )
            })
            .collect();

        let total = packages.len();
        println!("Quick scan: filtering to {} critical packages out of system total", total);

        {
            let mut progress = scan_state_clone.lock();
            progress.total_packages = total;
        }

        if packages.is_empty() {
            println!("WARNING: No critical packages found to scan!");
            let mut progress = scan_state_clone.lock();
            progress.status = ScanStatus::Complete;
            return;
        }

        let scanner = VulnerabilityScanner::new();
        let mut all_findings = Vec::new();

        // Scan each package with progress updates
        for (idx, package) in packages.iter().enumerate() {
            let scanned = idx + 1;
            let elapsed = start_time.elapsed().as_secs();
            let avg_time_per_pkg = if idx > 0 { elapsed / idx as u64 } else { 1 };
            let remaining_pkgs = total - scanned;
            let eta = avg_time_per_pkg * remaining_pkgs as u64;

            // Update progress
            {
                let mut progress = scan_state_clone.lock();
                progress.packages_scanned = scanned;
                progress.current_package = Some(format!("{} v{}", package.name, package.version));
                progress.elapsed_seconds = elapsed;
                progress.eta_seconds = Some(eta);
            }

            // Query CVE database
            let ecosystem = match package.source.as_str() {
                "dpkg" => "debian",
                "rpm" => "rhel",
                "pacman" => "arch",
                "apk" => "alpine",
                "windows_update" => "windows",
                _ => "unknown",
            };

            let findings = scanner.scan_packages_async(&[package.clone()]).await;

            if !findings.is_empty() {
                println!("  Quick Scan: Found {} CVEs in {} v{}", findings.len(), package.name, package.version);

                let critical_count = findings.iter()
                    .filter(|f| f.cve.severity == CVESeverity::Critical || f.cve.severity == CVESeverity::High)
                    .count();

                // Update vulnerability counts
                {
                    let mut progress = scan_state_clone.lock();
                    progress.vulnerabilities_found += findings.len();
                    progress.critical_threats += critical_count;
                }

                all_findings.extend(findings);
            }

            // Small delay to make progress visible
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }

        // Save findings to cache
        {
            let mut cache = findings_cache_clone.lock();
            *cache = all_findings.clone();
            println!("Saved {} findings to cache", all_findings.len());
        }

        // Mark scan complete
        {
            let mut progress = scan_state_clone.lock();
            progress.status = ScanStatus::Complete;
            progress.elapsed_seconds = start_time.elapsed().as_secs();
            progress.current_package = None;
            progress.eta_seconds = None;
        }

        println!("=== QUICK SCAN COMPLETE ===");
        println!("Scanned {} critical packages", total);
        println!("Found {} total vulnerabilities", all_findings.len());
        println!("========================");
    });

    Ok(())
}

#[tauri::command]
async fn scan_vulnerabilities(
    state: State<'_, ThreatDetectionState>,
    scan_state: State<'_, ScanProgressState>,
) -> Result<(), String> {
    println!("=== FULL VULNERABILITY SCAN STARTED ===");

    // Initialize scan progress
    {
        let mut progress = scan_state.lock();
        *progress = ScanProgress {
            status: ScanStatus::Scanning,
            scan_type: ScanType::Full,
            packages_scanned: 0,
            total_packages: 0,
            vulnerabilities_found: 0,
            critical_threats: 0,
            elapsed_seconds: 0,
            current_package: None,
            eta_seconds: None,
        };
    }

    // Clone state for background task
    let scan_state_clone = Arc::clone(&scan_state.inner());

    // Run scan in background
    tokio::spawn(async move {
        let start_time = std::time::Instant::now();

        #[cfg(target_os = "linux")]
        let sensor = match PackageSensor::new_linux() {
            Ok(s) => s,
            Err(e) => {
                println!("ERROR: Failed to create package sensor: {}", e);
                let mut progress = scan_state_clone.lock();
                progress.status = ScanStatus::Error;
                return;
            }
        };

        #[cfg(target_os = "windows")]
        let sensor = match PackageSensor::new_windows() {
            Ok(s) => s,
            Err(e) => {
                println!("ERROR: Failed to create package sensor: {}", e);
                let mut progress = scan_state_clone.lock();
                progress.status = ScanStatus::Error;
                return;
            }
        };

        #[cfg(target_os = "macos")]
        let sensor = match PackageSensor::new_macos() {
            Ok(s) => s,
            Err(e) => {
                println!("ERROR: Failed to create package sensor: {}", e);
                let mut progress = scan_state_clone.lock();
                progress.status = ScanStatus::Error;
                return;
            }
        };

        println!("Getting installed packages inventory...");
        let packages = sensor.get_inventory();
        let total = packages.len();
        println!("Found {} installed packages for full scan", total);

        {
            let mut progress = scan_state_clone.lock();
            progress.total_packages = total;
        }

        if packages.is_empty() {
            println!("WARNING: No packages found to scan!");
            let mut progress = scan_state_clone.lock();
            progress.status = ScanStatus::Complete;
            return;
        }

        let scanner = VulnerabilityScanner::new();
        let mut all_findings = Vec::new();

        // Scan each package with progress updates
        for (idx, package) in packages.iter().enumerate() {
            let scanned = idx + 1;
            let elapsed = start_time.elapsed().as_secs();
            let avg_time_per_pkg = if idx > 0 { elapsed / idx as u64 } else { 1 };
            let remaining_pkgs = total - scanned;
            let eta = avg_time_per_pkg * remaining_pkgs as u64;

            // Update progress
            {
                let mut progress = scan_state_clone.lock();
                progress.packages_scanned = scanned;
                progress.current_package = Some(format!("{} v{}", package.name, package.version));
                progress.elapsed_seconds = elapsed;
                progress.eta_seconds = Some(eta);
            }

            // Progress logging every 50 packages or for first/last
            if scanned == 1 || scanned == total || scanned % 50 == 0 {
                println!("Full Scan Progress: {}/{} packages scanned ({:.1}%)",
                    scanned, total, (scanned as f64 / total as f64) * 100.0);
            }

            // Query CVE database
            let ecosystem = match package.source.as_str() {
                "dpkg" => "debian",
                "rpm" => "rhel",
                "pacman" => "arch",
                "apk" => "alpine",
                "windows_update" => "windows",
                _ => "unknown",
            };

            let findings = scanner.scan_packages_async(&[package.clone()]).await;

            if !findings.is_empty() {
                println!("  Full Scan: Found {} CVEs in {} v{}", findings.len(), package.name, package.version);

                let critical_count = findings.iter()
                    .filter(|f| f.cve.severity == CVESeverity::Critical || f.cve.severity == CVESeverity::High)
                    .count();

                // Update vulnerability counts
                {
                    let mut progress = scan_state_clone.lock();
                    progress.vulnerabilities_found += findings.len();
                    progress.critical_threats += critical_count;
                }

                all_findings.extend(findings);
            }

            // Small delay to make progress visible
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }

        // Mark scan complete
        {
            let mut progress = scan_state_clone.lock();
            progress.status = ScanStatus::Complete;
            progress.elapsed_seconds = start_time.elapsed().as_secs();
            progress.current_package = None;
            progress.eta_seconds = None;
        }

        println!("=== FULL SCAN COMPLETE ===");
        println!("Scanned {} packages", total);
        println!("Found {} total vulnerabilities", all_findings.len());
        println!("=========================");
    });

    Ok(())
}

#[tauri::command]
async fn get_vulnerability_statistics() -> Result<ScanStatistics, String> {
    // For now, run a scan to get statistics
    // In production, cache scan results

    #[cfg(target_os = "linux")]
    let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let sensor = PackageSensor::new_windows().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    let sensor = PackageSensor::new_macos().map_err(|e| e.to_string())?;

    let packages = sensor.get_inventory();

    let scanner = VulnerabilityScanner::new();
    scanner.scan_packages(&packages);

    Ok(scanner.get_scan_stats())
}

#[tauri::command]
async fn get_prioritized_vulnerabilities() -> Result<Vec<PrioritizedFinding>, String> {
    #[cfg(target_os = "linux")]
    let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let sensor = PackageSensor::new_windows().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    let sensor = PackageSensor::new_macos().map_err(|e| e.to_string())?;

    let packages = sensor.get_inventory();

    let scanner = VulnerabilityScanner::new();
    let findings = scanner.scan_packages(&packages);

    let prioritized = VulnerabilityPrioritizer::prioritize(&findings);

    Ok(prioritized)
}

#[tauri::command]
async fn get_fix_now_list() -> Result<Vec<PrioritizedFinding>, String> {
    #[cfg(target_os = "linux")]
    let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let sensor = PackageSensor::new_windows().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    let sensor = PackageSensor::new_macos().map_err(|e| e.to_string())?;

    let packages = sensor.get_inventory();

    let scanner = VulnerabilityScanner::new();
    let findings = scanner.scan_packages(&packages);

    let prioritized = VulnerabilityPrioritizer::prioritize(&findings);
    let fix_now = VulnerabilityPrioritizer::get_fix_now_list(&prioritized);

    Ok(fix_now)
}

#[tauri::command]
async fn get_vulnerabilities_by_package(
    findings_cache: State<'_, VulnerabilityFindingsCache>,
) -> Result<Vec<PackageVulnerabilityGroup>, String> {
    // Return cached findings from last scan
    let findings = {
        let cache = findings_cache.lock();
        cache.clone()
    };

    // If cache is empty, return empty result (scan hasn't been run yet)
    if findings.is_empty() {
        return Ok(Vec::new());
    }

    // Group and prioritize the cached findings
    let prioritized = VulnerabilityPrioritizer::prioritize(&findings);
    let grouped = VulnerabilityPrioritizer::group_by_package(&prioritized);

    Ok(grouped)
}

#[tauri::command]
async fn scan_misconfigurations() -> Result<Vec<Misconfiguration>, String> {
    let scanner = MisconfigurationScanner::new();
    let findings = scanner.scan();

    Ok(findings)
}

#[tauri::command]
async fn get_exploitable_exposed() -> Result<Vec<VulnerabilityFinding>, String> {
    #[cfg(target_os = "linux")]
    let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let sensor = PackageSensor::new_windows().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    let sensor = PackageSensor::new_macos().map_err(|e| e.to_string())?;

    let packages = sensor.get_inventory();

    let scanner = VulnerabilityScanner::new();
    let findings = scanner.scan_packages(&packages);

    let exploitable = scanner.get_critical_exploitable();

    Ok(exploitable)
}

// ========================================
// Comprehensive System Scanner Commands
// ========================================

#[tauri::command]
async fn start_comprehensive_scan(
    scanner_state: State<'_, ComprehensiveScannerState>,
) -> Result<(), String> {
    println!("=== COMPREHENSIVE SYSTEM SCAN STARTED ===");

    // Create new scanner
    let scanner = ComprehensiveScanner::new();

    // Store scanner in state
    {
        let mut state = scanner_state.lock();
        *state = Some(scanner.clone());
    }

    // Clone for background task
    let scanner_clone = scanner.clone();

    // Run scan in background
    tokio::spawn(async move {
        let findings = scanner_clone.scan_system().await;
        println!("=== COMPREHENSIVE SCAN COMPLETE ===");
        println!("Found {} threats", findings.len());
        println!("=========================");
    });

    Ok(())
}

#[tauri::command]
async fn get_comprehensive_progress(
    scanner_state: State<'_, ComprehensiveScannerState>,
) -> Result<ComprehensiveScanProgress, String> {
    let state = scanner_state.lock();

    if let Some(scanner) = state.as_ref() {
        Ok(scanner.get_progress())
    } else {
        // Return default progress if no scan is running
        Ok(ComprehensiveScanProgress {
            scan_phase: ScanPhase::Initializing,
            total_items: 0,
            items_scanned: 0,
            threats_found: 0,
            critical_threats: 0,
            current_item: String::new(),
            elapsed_seconds: 0,
            eta_seconds: None,
        })
    }
}

// ========================================
// AI Analysis Commands
// ========================================

use ai_analysis::{SecurityAnalyzer, AnalysisResponse, SystemSecurityPosture, ReportConfiguration, ComprehensiveReport, ReportGenerator, ReportExporter};
use keychain::{KeychainManager, ApiKeyType};

// Malware Protection imports
use malware::{MalwareProtection, ProtectionConfig, ProtectionStatus};
use malware::scanner::ScanResult;
use malware::quarantine::QuarantinedFile;
use malware::sandbox::{SandboxEngine, SandboxConfig, SandboxResult, SandboxStats};
use malware::ransomware_protection::{RansomwareProtectionEngine, RansomwareConfig, RansomwareStats};
use malware::rootkit_detector::{RootKitDetector, RootkitDetectorConfig, RootkitDetection};
use malware::credential_theft_detector::{CredentialTheftDetector, CredentialDetectorConfig, CredentialThreat};
use malware::memory_scanner::{MemoryScanner, MemoryScanConfig, MemoryScanResult};
use malware::process_injection::{ProcessInjectionDetector, InjectionDetection};
use malware::behavioral_engine::{BehavioralEngine, BehavioralConfig, BehavioralDetection};
use malware::threat_intel::{ThreatIntelEngine, ThreatIntelConfig, Ioc, IocType, ThreatMatch};
use malware::incident_response::{IncidentResponseEngine, ResponseConfig, SecurityIncident, IncidentStatus};

#[tauri::command]
async fn analyze_vulnerabilities_with_ai() -> Result<AnalysisResponse, String> {
    println!("Starting AI vulnerability analysis...");

    // Get Claude API key
    let api_key = KeychainManager::load_api_key_with_fallback(
        ApiKeyType::Claude,
        "CLAUDE_API_KEY"
    );

    // Get vulnerabilities
    #[cfg(target_os = "linux")]
    let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let sensor = PackageSensor::new_windows().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    let sensor = PackageSensor::new_macos().map_err(|e| e.to_string())?;

    let packages = sensor.get_inventory();
    let scanner = VulnerabilityScanner::new();
    let vulnerabilities = scanner.scan_packages(&packages);

    if vulnerabilities.is_empty() {
        return Err("No vulnerabilities found to analyze".to_string());
    }

    // Analyze with AI
    let analyzer = SecurityAnalyzer::new(api_key);
    analyzer.analyze_vulnerabilities(&vulnerabilities).await
}

#[tauri::command]
async fn analyze_vulnerability_ai(
    cve_id: String,
    package_name: String,
    package_version: String,
    severity: String,
    summary: String,
    question: String,
) -> Result<String, String> {
    println!("AI analyzing {} with question: {}", cve_id, question);

    // Get Claude API key
    let api_key = KeychainManager::load_api_key_with_fallback(
        ApiKeyType::Claude,
        "CLAUDE_API_KEY"
    );

    if api_key.is_none() {
        return Err("Claude API key not configured. Please set up your API key in Settings.".to_string());
    }

    // Create analyzer and generate response
    let analyzer = SecurityAnalyzer::new(api_key);

    // Build context prompt
    let context = format!(
        "Vulnerability: {}\nPackage: {} version {}\nSeverity: {}\nDescription: {}\n\nUser Question: {}",
        cve_id, package_name, package_version, severity, summary, question
    );

    // Use AI to analyze and respond
    analyzer.chat_about_vulnerability(&context).await
}

#[tauri::command]
async fn analyze_security_posture() -> Result<SystemSecurityPosture, String> {
    println!("Starting AI security posture analysis...");

    // Get Claude API key
    let api_key = KeychainManager::load_api_key_with_fallback(
        ApiKeyType::Claude,
        "CLAUDE_API_KEY"
    );

    // Get all security data
    #[cfg(target_os = "linux")]
    let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let sensor = PackageSensor::new_windows().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    let sensor = PackageSensor::new_macos().map_err(|e| e.to_string())?;

    let packages = sensor.get_inventory();
    let vuln_scanner = VulnerabilityScanner::new();
    let vulnerabilities = vuln_scanner.scan_packages(&packages);

    let misconfig_scanner = MisconfigurationScanner::new();
    let misconfigurations = misconfig_scanner.scan();

    // Analyze with AI
    let analyzer = SecurityAnalyzer::new(api_key);
    analyzer.analyze_system_posture(&vulnerabilities, &[], &misconfigurations).await
}

#[tauri::command]
async fn generate_remediation_plan() -> Result<AnalysisResponse, String> {
    println!("Generating AI remediation plan...");

    // Get Claude API key
    let api_key = KeychainManager::load_api_key_with_fallback(
        ApiKeyType::Claude,
        "CLAUDE_API_KEY"
    );

    // Get vulnerabilities and misconfigurations
    #[cfg(target_os = "linux")]
    let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;

    #[cfg(target_os = "windows")]
    let sensor = PackageSensor::new_windows().map_err(|e| e.to_string())?;

    #[cfg(target_os = "macos")]
    let sensor = PackageSensor::new_macos().map_err(|e| e.to_string())?;

    let packages = sensor.get_inventory();
    let scanner = VulnerabilityScanner::new();
    let vulnerabilities = scanner.scan_packages(&packages);

    let misconfig_scanner = MisconfigurationScanner::new();
    let misconfigurations = misconfig_scanner.scan();

    // Generate plan with AI
    let analyzer = SecurityAnalyzer::new(api_key);
    analyzer.generate_remediation_plan(&vulnerabilities, &misconfigurations).await
}

// Report Generation Commands

#[tauri::command]
async fn generate_security_report(config: ReportConfiguration) -> Result<ComprehensiveReport, String> {
    println!("Generating comprehensive security report...");

    // Get Claude API key if AI analysis is requested
    let api_key = if config.include_ai_analysis {
        KeychainManager::load_api_key_with_fallback(
            ApiKeyType::Claude,
            "CLAUDE_API_KEY"
        )
    } else {
        None
    };

    let generator = ReportGenerator::new(api_key);
    generator.generate_report(config).await
}

#[tauri::command]
async fn export_report_html(report: ComprehensiveReport) -> Result<String, String> {
    println!("Exporting report as HTML...");
    Ok(ReportExporter::to_html(&report))
}

#[tauri::command]
async fn export_report_markdown(report: ComprehensiveReport) -> Result<String, String> {
    println!("Exporting report as Markdown...");
    Ok(ReportExporter::to_markdown(&report))
}

#[tauri::command]
async fn export_report_json(report: ComprehensiveReport) -> Result<String, String> {
    println!("Exporting report as JSON...");
    serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Failed to serialize report: {}", e))
}

// ========================================
// Hardware Detection & Tier System
// ========================================

use hardware_detector::{HardwareDetector, HardwareCapabilities, TierLevel};
use ollama::{OllamaClient, OllamaStatus};

#[tauri::command]
async fn detect_hardware() -> Result<HardwareCapabilities, String> {
    println!("Detecting hardware capabilities...");
    HardwareDetector::detect()
}

#[tauri::command]
async fn get_eligible_tiers() -> Result<Vec<(String, Vec<String>)>, String> {
    println!("Checking eligible tiers...");
    let capabilities = HardwareDetector::detect()?;
    let eligible = HardwareDetector::get_eligible_tiers(&capabilities);

    // Convert TierLevel enum to String for frontend
    let result = eligible.into_iter()
        .map(|(tier, warnings)| {
            let tier_name = match tier {
                TierLevel::Standard => "standard",
                TierLevel::Pro => "pro",
                TierLevel::Elite => "elite",
            };
            (tier_name.to_string(), warnings)
        })
        .collect();

    Ok(result)
}

#[tauri::command]
async fn check_ollama_status() -> Result<OllamaStatus, String> {
    println!("Checking Ollama status...");
    let client = OllamaClient::new();
    Ok(client.check_status().await)
}

#[tauri::command]
async fn list_ollama_models() -> Result<Vec<String>, String> {
    println!("Listing Ollama models...");
    let client = OllamaClient::new();
    let models = client.list_models().await?;
    Ok(models.into_iter().map(|m| m.name).collect())
}

#[tauri::command]
async fn pull_ollama_model(model_name: String) -> Result<(), String> {
    println!("Pulling Ollama model: {}", model_name);
    let client = OllamaClient::new();
    client.pull_model(&model_name).await
}

#[tauri::command]
async fn test_ollama_model(model_name: String) -> Result<bool, String> {
    println!("Testing Ollama model: {}", model_name);
    let client = OllamaClient::new();
    client.test_model(&model_name).await
}

#[tauri::command]
async fn analyze_vulnerability_ollama(
    model: String,
    cve_id: String,
    package_name: String,
    package_version: String,
    severity: String,
    summary: String,
    question: String,
) -> Result<String, String> {
    println!("Analyzing {} with Ollama model: {}", cve_id, model);

    let client = OllamaClient::new();
    client.analyze_vulnerability(
        &model,
        &cve_id,
        &package_name,
        &package_version,
        &severity,
        &summary,
        &question,
    ).await
}

// ========================================
// Malware Protection Commands
// ========================================

type MalwareProtectionState = Arc<Mutex<Option<MalwareProtection>>>;
type SandboxEngineState = Arc<Mutex<Option<SandboxEngine>>>;
type RansomwareProtectionState = Arc<Mutex<Option<RansomwareProtectionEngine>>>;
type RootkitDetectorState = Arc<Mutex<Option<RootKitDetector>>>;
type CredentialDetectorState = Arc<Mutex<Option<CredentialTheftDetector>>>;
type MemoryScannerState = Arc<Mutex<Option<MemoryScanner>>>;
type BehavioralEngineState = Arc<Mutex<Option<BehavioralEngine>>>;
type ThreatIntelState = Arc<Mutex<Option<ThreatIntelEngine>>>;
type IncidentResponseState = Arc<Mutex<Option<IncidentResponseEngine>>>;

/// Initialize malware protection system
#[tauri::command]
async fn init_malware_protection(
    state: State<'_, MalwareProtectionState>,
) -> Result<(), String> {
    log::info!("Initializing malware protection system");

    let config = ProtectionConfig::default();
    let protection = MalwareProtection::new(config)?;

    let mut guard = state.lock();
    *guard = Some(protection);

    Ok(())
}

/// Start real-time malware protection
#[tauri::command]
async fn start_malware_protection(
    state: State<'_, MalwareProtectionState>,
) -> Result<(), String> {
    let mut guard = state.lock();

    if let Some(protection) = guard.as_mut() {
        protection.start_real_time_protection()
    } else {
        Err("Malware protection not initialized".to_string())
    }
}

/// Stop real-time malware protection
#[tauri::command]
async fn stop_malware_protection(
    state: State<'_, MalwareProtectionState>,
) -> Result<(), String> {
    let mut guard = state.lock();

    if let Some(protection) = guard.as_mut() {
        protection.stop_real_time_protection();
        Ok(())
    } else {
        Err("Malware protection not initialized".to_string())
    }
}

/// Get malware protection status
#[tauri::command]
async fn get_malware_protection_status(
    state: State<'_, MalwareProtectionState>,
) -> Result<ProtectionStatus, String> {
    let guard = state.lock();

    if let Some(protection) = guard.as_ref() {
        Ok(protection.get_status())
    } else {
        Err("Malware protection not initialized".to_string())
    }
}

/// Scan a file for malware
#[tauri::command]
async fn scan_file_for_malware(
    state: State<'_, MalwareProtectionState>,
    file_path: String,
) -> Result<ScanResult, String> {
    let guard = state.lock();

    if let Some(protection) = guard.as_ref() {
        protection.scan_file(std::path::Path::new(&file_path))
    } else {
        Err("Malware protection not initialized".to_string())
    }
}

/// Quarantine a file
#[tauri::command]
async fn quarantine_file(
    state: State<'_, MalwareProtectionState>,
    file_path: String,
    scan_result: ScanResult,
) -> Result<QuarantinedFile, String> {
    let guard = state.lock();

    if let Some(protection) = guard.as_ref() {
        protection.quarantine_file(std::path::Path::new(&file_path), scan_result)
    } else {
        Err("Malware protection not initialized".to_string())
    }
}

// Sandbox Commands

/// Initialize sandbox engine
#[tauri::command]
async fn init_sandbox_engine(
    state: State<'_, SandboxEngineState>,
) -> Result<(), String> {
    let config = SandboxConfig::default();
    let engine = SandboxEngine::new(config)?;

    let mut guard = state.lock();
    *guard = Some(engine);

    Ok(())
}

/// Execute file in sandbox
#[tauri::command]
async fn execute_in_sandbox(
    state: State<'_, SandboxEngineState>,
    file_path: String,
) -> Result<String, String> {
    let mut guard = state.lock();

    if let Some(engine) = guard.as_mut() {
        engine.execute_in_sandbox(std::path::Path::new(&file_path))
    } else {
        Err("Sandbox engine not initialized".to_string())
    }
}

/// Get sandbox result
#[tauri::command]
async fn get_sandbox_result(
    state: State<'_, SandboxEngineState>,
    sandbox_id: String,
) -> Result<Option<SandboxResult>, String> {
    let guard = state.lock();

    if let Some(engine) = guard.as_ref() {
        Ok(engine.get_sandbox_result(&sandbox_id))
    } else {
        Err("Sandbox engine not initialized".to_string())
    }
}

/// Get sandbox statistics
#[tauri::command]
async fn get_sandbox_stats(
    state: State<'_, SandboxEngineState>,
) -> Result<SandboxStats, String> {
    let guard = state.lock();

    if let Some(engine) = guard.as_ref() {
        Ok(engine.get_stats())
    } else {
        Err("Sandbox engine not initialized".to_string())
    }
}

/// Terminate sandbox
#[tauri::command]
async fn terminate_sandbox(
    state: State<'_, SandboxEngineState>,
    sandbox_id: String,
) -> Result<(), String> {
    let mut guard = state.lock();

    if let Some(engine) = guard.as_mut() {
        engine.terminate_sandbox(&sandbox_id)
    } else {
        Err("Sandbox engine not initialized".to_string())
    }
}

// Ransomware Protection Commands

/// Initialize ransomware protection
#[tauri::command]
async fn init_ransomware_protection(
    state: State<'_, RansomwareProtectionState>,
) -> Result<(), String> {
    let config = RansomwareConfig::default();
    let engine = RansomwareProtectionEngine::new(config)?;

    let mut guard = state.lock();
    *guard = Some(engine);

    Ok(())
}

/// Deploy ransomware decoys
#[tauri::command]
async fn deploy_ransomware_decoys(
    state: State<'_, RansomwareProtectionState>,
) -> Result<usize, String> {
    let mut guard = state.lock();

    if let Some(engine) = guard.as_mut() {
        engine.deploy_decoys()
    } else {
        Err("Ransomware protection not initialized".to_string())
    }
}

/// Add protected directory
#[tauri::command]
async fn add_protected_directory(
    state: State<'_, RansomwareProtectionState>,
    directory: String,
) -> Result<(), String> {
    let mut guard = state.lock();

    if let Some(engine) = guard.as_mut() {
        engine.add_protected_directory(std::path::PathBuf::from(directory))
    } else {
        Err("Ransomware protection not initialized".to_string())
    }
}

/// Get ransomware statistics
#[tauri::command]
async fn get_ransomware_stats(
    state: State<'_, RansomwareProtectionState>,
) -> Result<RansomwareStats, String> {
    let guard = state.lock();

    if let Some(engine) = guard.as_ref() {
        Ok(engine.get_stats())
    } else {
        Err("Ransomware protection not initialized".to_string())
    }
}

// Rootkit Detection Commands

/// Initialize rootkit detector
#[tauri::command]
async fn init_rootkit_detector(
    state: State<'_, RootkitDetectorState>,
) -> Result<(), String> {
    let config = RootkitDetectorConfig::default();
    let detector = RootKitDetector::new(config)?;

    let mut guard = state.lock();
    *guard = Some(detector);

    Ok(())
}

/// Run rootkit scan
#[tauri::command]
async fn scan_for_rootkits(
    state: State<'_, RootkitDetectorState>,
) -> Result<Vec<RootkitDetection>, String> {
    let mut guard = state.lock();

    if let Some(detector) = guard.as_mut() {
        detector.scan()
    } else {
        Err("Rootkit detector not initialized".to_string())
    }
}

// Credential Theft Detection Commands

/// Initialize credential theft detector
#[tauri::command]
async fn init_credential_detector(
    state: State<'_, CredentialDetectorState>,
) -> Result<(), String> {
    let config = CredentialDetectorConfig::default();
    let detector = CredentialTheftDetector::new(config)?;

    let mut guard = state.lock();
    *guard = Some(detector);

    Ok(())
}

/// Detect LSASS access
#[tauri::command]
async fn detect_lsass_access(
    state: State<'_, CredentialDetectorState>,
    process_id: u32,
    process_name: String,
) -> Result<Option<CredentialThreat>, String> {
    let mut guard = state.lock();

    if let Some(detector) = guard.as_mut() {
        detector.detect_lsass_access(
            process_id,
            &process_name,
            malware::credential_theft_detector::LsassAccessType::MemoryRead,
        )
    } else {
        Err("Credential detector not initialized".to_string())
    }
}

// Memory Scanner Commands

/// Initialize memory scanner
#[tauri::command]
async fn init_memory_scanner(
    state: State<'_, MemoryScannerState>,
) -> Result<(), String> {
    let config = MemoryScanConfig::default();
    let scanner = MemoryScanner::new(config);

    let mut guard = state.lock();
    *guard = Some(scanner);

    Ok(())
}

/// Scan process memory
#[tauri::command]
async fn scan_process_memory(
    state: State<'_, MemoryScannerState>,
    process_id: u32,
) -> Result<MemoryScanResult, String> {
    let mut guard = state.lock();

    if let Some(scanner) = guard.as_mut() {
        scanner.scan_process(process_id)
    } else {
        Err("Memory scanner not initialized".to_string())
    }
}

// Behavioral Engine Commands

/// Initialize behavioral engine
#[tauri::command]
async fn init_behavioral_engine(
    state: State<'_, BehavioralEngineState>,
) -> Result<(), String> {
    let config = BehavioralConfig::default();
    let engine = BehavioralEngine::new(config);

    let mut guard = state.lock();
    *guard = Some(engine);

    Ok(())
}

/// Track process behavior
#[tauri::command]
async fn track_process_behavior(
    state: State<'_, BehavioralEngineState>,
    process_id: u32,
    process_name: String,
    behavior_type: String,
) -> Result<Vec<BehavioralDetection>, String> {
    let mut guard = state.lock();

    if let Some(engine) = guard.as_mut() {
        // Parse behavior type and call appropriate method
        Ok(Vec::new()) // Simplified for now
    } else {
        Err("Behavioral engine not initialized".to_string())
    }
}

// Threat Intelligence Commands

/// Initialize threat intelligence engine
#[tauri::command]
async fn init_threat_intel(
    state: State<'_, ThreatIntelState>,
) -> Result<(), String> {
    let config = ThreatIntelConfig::default();
    let engine = ThreatIntelEngine::new(config);

    let mut guard = state.lock();
    *guard = Some(engine);

    Ok(())
}

/// Check IOC (simplified - assumes IP address type)
#[tauri::command]
async fn check_ioc(
    state: State<'_, ThreatIntelState>,
    ioc_value: String,
    ioc_type_str: String,
) -> Result<Option<ThreatMatch>, String> {
    let mut guard = state.lock();

    if let Some(engine) = guard.as_mut() {
        // Parse IOC type from string
        let ioc_type = match ioc_type_str.as_str() {
            "ip" => IocType::IpAddress,
            "domain" => IocType::Domain,
            "url" => IocType::Url,
            "hash" => IocType::FileHash,
            "email" => IocType::Email,
            _ => return Err(format!("Unknown IOC type: {}", ioc_type_str)),
        };

        Ok(engine.check_ioc(&ioc_type, &ioc_value))
    } else {
        Err("Threat intelligence not initialized".to_string())
    }
}

// Incident Response Commands

/// Initialize incident response engine
#[tauri::command]
async fn init_incident_response(
    state: State<'_, IncidentResponseState>,
) -> Result<(), String> {
    let config = ResponseConfig::default();
    let engine = IncidentResponseEngine::new(config);

    let mut guard = state.lock();
    *guard = Some(engine);

    Ok(())
}

/// Get recent incidents
#[tauri::command]
async fn get_active_incidents(
    state: State<'_, IncidentResponseState>,
    limit: usize,
) -> Result<Vec<SecurityIncident>, String> {
    let guard = state.lock();

    if let Some(engine) = guard.as_ref() {
        Ok(engine.get_recent_incidents(limit))
    } else {
        Err("Incident response not initialized".to_string())
    }
}

/// Get incident by ID (finds in all incidents)
#[tauri::command]
async fn get_incident(
    state: State<'_, IncidentResponseState>,
    incident_id: String,
) -> Result<Option<SecurityIncident>, String> {
    let guard = state.lock();

    if let Some(engine) = guard.as_ref() {
        // Search through all incidents
        let incidents = engine.get_incidents();
        Ok(incidents.iter()
            .find(|i| i.id == incident_id)
            .cloned())
    } else {
        Err("Incident response not initialized".to_string())
    }
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

    // Initialize scan progress state
    let scan_progress = Arc::new(Mutex::new(ScanProgress::default()));

    // Initialize comprehensive scanner state
    let comprehensive_scanner = Arc::new(Mutex::new(None::<ComprehensiveScanner>));

    // Initialize vulnerability findings cache
    let findings_cache = Arc::new(Mutex::new(Vec::<VulnerabilityFinding>::new()));

    // Initialize malware protection state management
    let malware_protection = Arc::new(Mutex::new(None::<MalwareProtection>));
    let sandbox_engine = Arc::new(Mutex::new(None::<SandboxEngine>));
    let ransomware_protection = Arc::new(Mutex::new(None::<RansomwareProtectionEngine>));
    let rootkit_detector = Arc::new(Mutex::new(None::<RootKitDetector>));
    let credential_detector = Arc::new(Mutex::new(None::<CredentialTheftDetector>));
    let memory_scanner = Arc::new(Mutex::new(None::<MemoryScanner>));
    let behavioral_engine = Arc::new(Mutex::new(None::<BehavioralEngine>));
    let threat_intel = Arc::new(Mutex::new(None::<ThreatIntelEngine>));
    let incident_response = Arc::new(Mutex::new(None::<IncidentResponseEngine>));

    tauri::Builder::default()
        .manage(service)
        .manage(threat_engine)
        .manage(scan_progress)
        .manage(comprehensive_scanner)
        .manage(findings_cache)
        .manage(malware_protection)
        .manage(sandbox_engine)
        .manage(ransomware_protection)
        .manage(rootkit_detector)
        .manage(credential_detector)
        .manage(memory_scanner)
        .manage(behavioral_engine)
        .manage(threat_intel)
        .manage(incident_response)
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
            get_configured_api_keys,
            // Network Security
            get_network_connections,
            get_top_talkers,
            get_connection_stats,
            analyze_dns_query,
            classify_ip,
            get_segment_policies,
            update_segment_policy,
            lookup_ip_info,
            preview_isolation_action,
            execute_isolation_action,
            rollback_isolation,
            get_isolation_history,
            // Vulnerability Scanning
            get_scan_progress,
            start_quick_scan,
            scan_vulnerabilities,
            get_vulnerability_statistics,
            get_prioritized_vulnerabilities,
            get_fix_now_list,
            get_vulnerabilities_by_package,
            scan_misconfigurations,
            get_exploitable_exposed,
            // Comprehensive System Scanner
            start_comprehensive_scan,
            get_comprehensive_progress,
            // AI Analysis
            analyze_vulnerabilities_with_ai,
            analyze_vulnerability_ai,
            analyze_security_posture,
            generate_remediation_plan,
            // Security Reports
            generate_security_report,
            export_report_html,
            export_report_markdown,
            export_report_json,
            // Hardware Detection & Tier System
            detect_hardware,
            get_eligible_tiers,
            check_ollama_status,
            list_ollama_models,
            pull_ollama_model,
            test_ollama_model,
            analyze_vulnerability_ollama,
            // Malware Protection
            init_malware_protection,
            start_malware_protection,
            stop_malware_protection,
            get_malware_protection_status,
            scan_file_for_malware,
            quarantine_file,
            // Sandbox
            init_sandbox_engine,
            execute_in_sandbox,
            get_sandbox_result,
            get_sandbox_stats,
            terminate_sandbox,
            // Ransomware Protection
            init_ransomware_protection,
            deploy_ransomware_decoys,
            add_protected_directory,
            get_ransomware_stats,
            // Rootkit Detection
            init_rootkit_detector,
            scan_for_rootkits,
            // Credential Theft Detection
            init_credential_detector,
            detect_lsass_access,
            // Memory Scanner
            init_memory_scanner,
            scan_process_memory,
            // Behavioral Engine
            init_behavioral_engine,
            track_process_behavior,
            // Threat Intelligence
            init_threat_intel,
            check_ioc,
            // Incident Response
            init_incident_response,
            get_active_incidents,
            get_incident
        ])
        .on_window_event(|_window, _event| {})
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}