// Package Sensor - monitors installed packages for inventory and vulnerability tracking

use super::*;
use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use parking_lot::Mutex;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: Option<String>,
    pub source: String, // dpkg, rpm, pacman, apk
}

pub struct PackageSensor {
    running: bool,
    events: Arc<Mutex<Vec<SecurityEvent>>>,
    known_packages: Arc<Mutex<HashMap<String, Package>>>,
    package_manager: PackageManager,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PackageManager {
    Dpkg,   // Debian/Ubuntu
    Rpm,    // RHEL/Fedora/CentOS
    Pacman, // Arch Linux
    Apk,    // Alpine Linux
    None,
}

impl PackageSensor {
    #[cfg(target_os = "linux")]
    pub fn new_linux() -> Result<Self, Box<dyn std::error::Error>> {
        let package_manager = Self::detect_package_manager();

        let sensor = Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_packages: Arc::new(Mutex::new(HashMap::new())),
            package_manager,
        };

        // Perform initial scan to populate known_packages
        let packages = match package_manager {
            PackageManager::Dpkg => Self::get_dpkg_packages(),
            PackageManager::Rpm => Self::get_rpm_packages(),
            PackageManager::Pacman => Self::get_pacman_packages(),
            PackageManager::Apk => Self::get_apk_packages(),
            PackageManager::None => Vec::new(),
        };

        // Populate known_packages with initial scan
        {
            let mut known = sensor.known_packages.lock();
            for pkg in packages {
                known.insert(format!("{}:{}", pkg.name, pkg.version), pkg);
            }
        }

        println!("PackageSensor initialized with {} packages", sensor.get_package_count());

        Ok(sensor)
    }

    #[cfg(target_os = "windows")]
    pub fn new_windows() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_packages: Arc::new(Mutex::new(HashMap::new())),
            package_manager: PackageManager::None,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn new_macos() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_packages: Arc::new(Mutex::new(HashMap::new())),
            package_manager: PackageManager::None,
        })
    }

    #[cfg(target_os = "linux")]
    /// Detect which package manager is available
    fn detect_package_manager() -> PackageManager {
        // Check for dpkg (Debian/Ubuntu)
        if std::path::Path::new("/usr/bin/dpkg").exists()
            || std::path::Path::new("/bin/dpkg").exists() {
            return PackageManager::Dpkg;
        }

        // Check for rpm (RHEL/Fedora/CentOS)
        if std::path::Path::new("/usr/bin/rpm").exists()
            || std::path::Path::new("/bin/rpm").exists() {
            return PackageManager::Rpm;
        }

        // Check for pacman (Arch)
        if std::path::Path::new("/usr/bin/pacman").exists()
            || std::path::Path::new("/bin/pacman").exists() {
            return PackageManager::Pacman;
        }

        // Check for apk (Alpine)
        if std::path::Path::new("/sbin/apk").exists() {
            return PackageManager::Apk;
        }

        PackageManager::None
    }

    #[cfg(target_os = "linux")]
    /// Get installed packages using dpkg
    fn get_dpkg_packages() -> Vec<Package> {
        let mut packages = Vec::new();

        // Run dpkg-query to get installed packages
        let output = Command::new("dpkg-query")
            .args(&["-W", "-f=${Package}\t${Version}\t${Architecture}\n"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 2 {
                        packages.push(Package {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            architecture: parts.get(2).map(|s| s.to_string()),
                            source: "dpkg".to_string(),
                        });
                    }
                }
            }
        }

        packages
    }

    #[cfg(target_os = "linux")]
    /// Get installed packages using rpm
    fn get_rpm_packages() -> Vec<Package> {
        let mut packages = Vec::new();

        // Run rpm to get installed packages
        let output = Command::new("rpm")
            .args(&["-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    if parts.len() >= 2 {
                        packages.push(Package {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            architecture: parts.get(2).map(|s| s.to_string()),
                            source: "rpm".to_string(),
                        });
                    }
                }
            }
        }

        packages
    }

    #[cfg(target_os = "linux")]
    /// Get installed packages using pacman
    fn get_pacman_packages() -> Vec<Package> {
        let mut packages = Vec::new();

        // Run pacman to get installed packages
        let output = Command::new("pacman")
            .args(&["-Q"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        packages.push(Package {
                            name: parts[0].to_string(),
                            version: parts[1].to_string(),
                            architecture: None, // pacman doesn't show arch in -Q
                            source: "pacman".to_string(),
                        });
                    }
                }
            }
        }

        packages
    }

    #[cfg(target_os = "linux")]
    /// Get installed packages using apk
    fn get_apk_packages() -> Vec<Package> {
        let mut packages = Vec::new();

        // Run apk to get installed packages
        let output = Command::new("apk")
            .args(&["info", "-v"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    // Format: package-version
                    if let Some(dash_pos) = line.rfind('-') {
                        let name = &line[..dash_pos];
                        let version = &line[dash_pos + 1..];
                        packages.push(Package {
                            name: name.to_string(),
                            version: version.to_string(),
                            architecture: None,
                            source: "apk".to_string(),
                        });
                    }
                }
            }
        }

        packages
    }

    #[cfg(target_os = "linux")]
    /// Get all installed packages based on detected package manager
    fn get_packages(&self) -> Vec<Package> {
        match self.package_manager {
            PackageManager::Dpkg => Self::get_dpkg_packages(),
            PackageManager::Rpm => Self::get_rpm_packages(),
            PackageManager::Pacman => Self::get_pacman_packages(),
            PackageManager::Apk => Self::get_apk_packages(),
            PackageManager::None => Vec::new(),
        }
    }

    #[cfg(target_os = "linux")]
    /// Create a package installed event
    fn create_package_event(package: &Package) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ServiceInstalled);
        event.severity = EventSeverity::Info;

        event.add_tag("package");
        event.add_tag("inventory");
        event.add_tag(&package.source);

        // Check for suspicious package names
        let suspicious_keywords = vec![
            "miner", "xmrig", "monero", "bitcoin", "crypto",
            "backdoor", "rootkit", "keylog",
        ];

        let package_lower = package.name.to_lowercase();
        for keyword in suspicious_keywords {
            if package_lower.contains(keyword) {
                event.add_tag("suspicious");
                event.severity = EventSeverity::High;
                break;
            }
        }

        event
    }

    // ===== Windows-specific implementations =====

    #[cfg(target_os = "windows")]
    /// Get installed Windows updates (KBs) via WMI
    fn get_windows_kbs() -> Vec<Package> {
        use wmi::{COMLibrary, WMIConnection};
        use std::collections::HashMap;

        let mut packages = Vec::new();

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::new(com_con) {
                let results: Result<Vec<HashMap<String, wmi::Variant>>, _> = wmi_con.raw_query(
                    "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering"
                );

                if let Ok(results) = results {
                    for result in results {
                        let kb_id = result.get("HotFixID")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();

                        let description = result.get("Description")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_else(|| "Update".to_string());

                        let installed_on = result.get("InstalledOn")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_else(|| "Unknown".to_string());

                        if !kb_id.is_empty() {
                            packages.push(Package {
                                name: kb_id.clone(),
                                version: installed_on,
                                architecture: Some(description),
                                source: "windows_update".to_string(),
                            });
                        }
                    }
                }
            }
        }

        packages
    }

    #[cfg(target_os = "windows")]
    fn detect_package_manager() -> PackageManager {
        PackageManager::None // Windows uses WMI directly
    }

    #[cfg(target_os = "windows")]
    fn get_packages(&self) -> Vec<Package> {
        Self::get_windows_kbs()
    }

    #[cfg(target_os = "windows")]
    fn create_package_event(package: &Package) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ServiceInstalled);
        event.severity = EventSeverity::Info;

        event.add_tag("package");
        event.add_tag("inventory");
        event.add_tag("windows_update");
        event.add_tag("kb");

        // Check for critical/important security updates
        if let Some(desc) = &package.architecture {
            let desc_lower = desc.to_lowercase();
            if desc_lower.contains("security") || desc_lower.contains("critical") {
                event.add_tag("security_update");
                event.severity = EventSeverity::Medium;
            }
        }

        event
    }

    // ===== Stub implementations for non-Linux, non-Windows platforms =====

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn detect_package_manager() -> PackageManager {
        PackageManager::None
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_packages(&self) -> Vec<Package> {
        Vec::new()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn create_package_event(_package: &Package) -> SecurityEvent {
        SecurityEvent::new(EventType::ServiceInstalled)
    }
}

#[async_trait::async_trait]
impl EventCollector for PackageSensor {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running = true;

        #[cfg(target_os = "linux")]
        {
            if self.package_manager == PackageManager::None {
                return Ok(());
            }

            // Initialize known packages
            let packages = self.get_packages();

            let mut known = self.known_packages.lock();
            for package in packages {
                let key = format!("{}:{}", package.source, package.name);
                known.insert(key, package);
            }
            drop(known);

            // Start background monitoring for new packages
            let known_packages = Arc::clone(&self.known_packages);
            let events = Arc::clone(&self.events);
            let package_manager = self.package_manager;

            tokio::spawn(async move {
                // Check for new packages every 5 minutes (packages change infrequently)
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));

                loop {
                    interval.tick().await;

                    let packages = match package_manager {
                        PackageManager::Dpkg => PackageSensor::get_dpkg_packages(),
                        PackageManager::Rpm => PackageSensor::get_rpm_packages(),
                        PackageManager::Pacman => PackageSensor::get_pacman_packages(),
                        PackageManager::Apk => PackageSensor::get_apk_packages(),
                        PackageManager::None => Vec::new(),
                    };

                    let mut known = known_packages.lock();

                    for package in packages {
                        let key = format!("{}:{}", package.source, package.name);

                        if !known.contains_key(&key) {
                            // New package detected
                            let event = PackageSensor::create_package_event(&package);
                            events.lock().push(event);
                            known.insert(key, package);
                        } else {
                            // Check for version changes (updates)
                            if let Some(existing) = known.get(&key) {
                                if existing.version != package.version {
                                    // Update the stored version
                                    known.insert(key.clone(), package.clone());
                                }
                            }
                        }
                    }
                }
            });
        }

        #[cfg(target_os = "windows")]
        {
            // Initialize known KBs
            let packages = self.get_packages();

            let mut known = self.known_packages.lock();
            for package in packages {
                let key = format!("{}:{}", package.source, package.name);
                known.insert(key, package);
            }
            drop(known);

            // Start background monitoring for new Windows updates
            let known_packages = Arc::clone(&self.known_packages);
            let events = Arc::clone(&self.events);

            tokio::spawn(async move {
                // Check for new Windows updates every 5 minutes
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));

                loop {
                    interval.tick().await;

                    let packages = PackageSensor::get_windows_kbs();
                    let mut known = known_packages.lock();

                    for package in packages {
                        let key = format!("{}:{}", package.source, package.name);

                        if !known.contains_key(&key) {
                            // New KB detected
                            let event = PackageSensor::create_package_event(&package);
                            events.lock().push(event);
                            known.insert(key, package);
                        }
                    }
                }
            });
        }

        Ok(())
    }

    async fn stop(&mut self) {
        self.running = false;
    }

    async fn collect_events(&mut self) -> Vec<SecurityEvent> {
        let mut events = self.events.lock();
        events.drain(..).collect()
    }

    fn is_running(&self) -> bool {
        self.running
    }
}

impl PackageSensor {
    /// Get current package inventory (for queries)
    pub fn get_inventory(&self) -> Vec<Package> {
        let known = self.known_packages.lock();
        known.values().cloned().collect()
    }

    /// Get package count
    pub fn get_package_count(&self) -> usize {
        self.known_packages.lock().len()
    }

    /// Search for a specific package
    pub fn find_package(&self, name: &str) -> Option<Package> {
        let known = self.known_packages.lock();
        known.values()
            .find(|p| p.name.to_lowercase().contains(&name.to_lowercase()))
            .cloned()
    }
}
