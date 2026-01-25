// Persistence Sensor - monitors autoruns, services, scheduled tasks

use super::*;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use parking_lot::Mutex;

pub struct PersistenceSensor {
    running: bool,
    events: Arc<Mutex<Vec<SecurityEvent>>>,
    known_services: Arc<Mutex<HashSet<String>>>,
    known_timers: Arc<Mutex<HashSet<String>>>,
    known_cron_files: Arc<Mutex<HashSet<String>>>,
    known_autostart: Arc<Mutex<HashSet<String>>>,
}

impl PersistenceSensor {
    #[cfg(target_os = "linux")]
    pub fn new_linux() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_services: Arc::new(Mutex::new(HashSet::new())),
            known_timers: Arc::new(Mutex::new(HashSet::new())),
            known_cron_files: Arc::new(Mutex::new(HashSet::new())),
            known_autostart: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_windows() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_services: Arc::new(Mutex::new(HashSet::new())),
            known_timers: Arc::new(Mutex::new(HashSet::new())),
            known_cron_files: Arc::new(Mutex::new(HashSet::new())),
            known_autostart: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    #[cfg(target_os = "macos")]
    pub fn new_macos() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            events: Arc::new(Mutex::new(Vec::new())),
            known_services: Arc::new(Mutex::new(HashSet::new())),
            known_timers: Arc::new(Mutex::new(HashSet::new())),
            known_cron_files: Arc::new(Mutex::new(HashSet::new())),
            known_autostart: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    #[cfg(target_os = "linux")]
    /// Get list of enabled systemd services
    fn get_systemd_services() -> Vec<String> {
        let mut services = Vec::new();

        // Check /etc/systemd/system and /usr/lib/systemd/system
        let paths = vec![
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ];

        for path in paths {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(name) = path.file_name() {
                        if let Some(name_str) = name.to_str() {
                            if name_str.ends_with(".service") && !path.is_symlink() {
                                services.push(name_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        services
    }

    #[cfg(target_os = "linux")]
    /// Get list of systemd timers
    fn get_systemd_timers() -> Vec<String> {
        let mut timers = Vec::new();

        let paths = vec![
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/lib/systemd/system",
        ];

        for path in paths {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(name) = path.file_name() {
                        if let Some(name_str) = name.to_str() {
                            if name_str.ends_with(".timer") {
                                timers.push(name_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        timers
    }

    #[cfg(target_os = "linux")]
    /// Get cron job files
    fn get_cron_files() -> Vec<String> {
        let mut cron_files = Vec::new();

        // System cron
        let system_cron_paths = vec![
            "/etc/crontab",
            "/etc/cron.d",
            "/etc/cron.hourly",
            "/etc/cron.daily",
            "/etc/cron.weekly",
            "/etc/cron.monthly",
        ];

        for path in system_cron_paths {
            if Path::new(path).exists() {
                if Path::new(path).is_file() {
                    cron_files.push(path.to_string());
                } else if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        cron_files.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
        }

        // User crontabs
        if let Ok(entries) = fs::read_dir("/var/spool/cron/crontabs") {
            for entry in entries.flatten() {
                cron_files.push(entry.path().to_string_lossy().to_string());
            }
        }

        cron_files
    }

    #[cfg(target_os = "linux")]
    /// Get autostart files
    fn get_autostart_files() -> Vec<String> {
        let mut autostart_files = Vec::new();

        // System-wide autostart
        let system_autostart = vec![
            "/etc/xdg/autostart",
            "/usr/share/autostart",
        ];

        for path in system_autostart {
            if let Ok(entries) = fs::read_dir(path) {
                for entry in entries.flatten() {
                    if entry.path().extension().and_then(|s| s.to_str()) == Some("desktop") {
                        autostart_files.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
        }

        // User autostart (~/.config/autostart)
        if let Ok(home) = std::env::var("HOME") {
            let user_autostart = format!("{}/.config/autostart", home);
            if let Ok(entries) = fs::read_dir(&user_autostart) {
                for entry in entries.flatten() {
                    if entry.path().extension().and_then(|s| s.to_str()) == Some("desktop") {
                        autostart_files.push(entry.path().to_string_lossy().to_string());
                    }
                }
            }
        }

        autostart_files
    }

    #[cfg(target_os = "linux")]
    /// Create a service installed event
    fn create_service_event(service_name: &str) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ServiceInstalled);
        event.severity = EventSeverity::Medium;

        event.add_tag("persistence");
        event.add_tag("systemd");
        event.add_tag("service");

        // Check for suspicious service names
        let suspicious_keywords = vec![
            "backdoor", "reverse", "shell", "netcat", "nc", "socat",
            "miner", "crypto", "xmrig", "monero", "bitcoin",
        ];

        let service_lower = service_name.to_lowercase();
        for keyword in suspicious_keywords {
            if service_lower.contains(keyword) {
                event.add_tag("suspicious");
                event.severity = EventSeverity::High;
                event.set_mitre(
                    vec!["Persistence".to_string()],
                    vec!["T1543.002".to_string()], // Systemd Service
                );
                break;
            }
        }

        event
    }

    #[cfg(target_os = "linux")]
    /// Create a timer created event
    fn create_timer_event(timer_name: &str) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ScheduledTaskCreated);
        event.severity = EventSeverity::Medium;

        event.add_tag("persistence");
        event.add_tag("systemd");
        event.add_tag("timer");

        event.set_mitre(
            vec!["Persistence".to_string(), "Execution".to_string()],
            vec!["T1053.006".to_string()], // Systemd Timers
        );

        event
    }

    #[cfg(target_os = "linux")]
    /// Create a cron job event
    fn create_cron_event(cron_file: &str) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ScheduledTaskCreated);
        event.severity = EventSeverity::Medium;

        event.add_tag("persistence");
        event.add_tag("cron");

        event.set_mitre(
            vec!["Persistence".to_string(), "Execution".to_string()],
            vec!["T1053.003".to_string()], // Cron
        );

        // Check for suspicious cron entries
        if let Ok(content) = fs::read_to_string(cron_file) {
            let suspicious_patterns = vec![
                "curl", "wget", "nc", "netcat", "/dev/tcp", "/dev/udp",
                "bash -i", "sh -i", "/tmp/", "chmod +x",
            ];

            for pattern in suspicious_patterns {
                if content.contains(pattern) {
                    event.add_tag("suspicious");
                    event.severity = EventSeverity::High;
                    break;
                }
            }
        }

        event
    }

    #[cfg(target_os = "linux")]
    /// Create an autostart event
    fn create_autostart_event(autostart_file: &str) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ServiceInstalled);
        event.severity = EventSeverity::Info;

        event.add_tag("persistence");
        event.add_tag("autostart");

        event.set_mitre(
            vec!["Persistence".to_string()],
            vec!["T1547.001".to_string()], // Boot or Logon Autostart Execution
        );

        // Read .desktop file to check Exec line
        if let Ok(content) = fs::read_to_string(autostart_file) {
            for line in content.lines() {
                if line.starts_with("Exec=") {
                    let exec_command = line.trim_start_matches("Exec=");

                    // Check for suspicious commands
                    let suspicious_patterns = vec![
                        "curl", "wget", "nc", "netcat", "/tmp/", "chmod", "bash -c", "sh -c",
                    ];

                    for pattern in suspicious_patterns {
                        if exec_command.contains(pattern) {
                            event.add_tag("suspicious");
                            event.severity = EventSeverity::High;
                            break;
                        }
                    }

                    break;
                }
            }
        }

        event
    }

    // ===== Windows-specific implementations =====

    #[cfg(target_os = "windows")]
    /// Get Windows services via WMI
    fn get_windows_services() -> Vec<WindowsService> {
        use wmi::{COMLibrary, WMIConnection};
        use std::collections::HashMap;

        let mut services = Vec::new();

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::new(com_con) {
                let results: Result<Vec<HashMap<String, wmi::Variant>>, _> = wmi_con.raw_query(
                    "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service"
                );

                if let Ok(results) = results {
                    for result in results {
                        let name = result.get("Name")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let display_name = result.get("DisplayName")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let state = result.get("State")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let start_mode = result.get("StartMode")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let path_name = result.get("PathName")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();

                        services.push(WindowsService {
                            name,
                            display_name,
                            state,
                            start_mode,
                            path_name,
                        });
                    }
                }
            }
        }

        services
    }

    #[cfg(target_os = "windows")]
    /// Get scheduled tasks via WMI
    fn get_scheduled_tasks() -> Vec<ScheduledTask> {
        use wmi::{COMLibrary, WMIConnection};
        use std::collections::HashMap;

        let mut tasks = Vec::new();

        if let Ok(com_con) = COMLibrary::new() {
            if let Ok(wmi_con) = WMIConnection::new(com_con) {
                let results: Result<Vec<HashMap<String, wmi::Variant>>, _> = wmi_con.raw_query(
                    "SELECT TaskName, Enabled, State, Author FROM MSFT_ScheduledTask"
                );

                if let Ok(results) = results {
                    for result in results {
                        let task_name = result.get("TaskName")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let enabled = result.get("Enabled")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                wmi::Variant::Bool(b) => Some(b.to_string()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let state = result.get("State")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();
                        let author = result.get("Author")
                            .and_then(|v| match v {
                                wmi::Variant::String(s) => Some(s.clone()),
                                _ => None,
                            })
                            .unwrap_or_default();

                        tasks.push(ScheduledTask {
                            name: task_name,
                            enabled,
                            state,
                            author,
                        });
                    }
                }
            }
        }

        tasks
    }

    #[cfg(target_os = "windows")]
    /// Get registry autoruns (Run, RunOnce, etc.)
    fn get_registry_autoruns() -> Vec<RegistryAutorun> {
        use windows::Win32::System::Registry::*;

        let mut autoruns = Vec::new();

        let run_keys = vec![
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        ];

        for (hkey, subkey) in run_keys {
            if let Ok(entries) = Self::read_registry_key(hkey, subkey) {
                for (name, value) in entries {
                    autoruns.push(RegistryAutorun {
                        hive: if hkey == HKEY_LOCAL_MACHINE { "HKLM".to_string() } else { "HKCU".to_string() },
                        key: subkey.to_string(),
                        name,
                        value,
                    });
                }
            }
        }

        autoruns
    }

    #[cfg(target_os = "windows")]
    /// Read registry key values
    fn read_registry_key(hkey: windows::Win32::System::Registry::HKEY, subkey: &str) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        use windows::Win32::System::Registry::*;
        use windows::core::PCWSTR;
        use std::os::windows::ffi::OsStrExt;
        use std::ffi::OsStr;

        let mut values = Vec::new();

        unsafe {
            let subkey_wide: Vec<u16> = OsStr::new(subkey).encode_wide().chain(Some(0)).collect();
            let mut key: windows::Win32::System::Registry::HKEY = Default::default();

            if RegOpenKeyExW(hkey, PCWSTR(subkey_wide.as_ptr()), 0, KEY_READ, &mut key).is_ok() {
                let mut index = 0;
                loop {
                    let mut name_buf = vec![0u16; 256];
                    let mut name_len = name_buf.len() as u32;
                    let mut value_buf = vec![0u8; 1024];
                    let mut value_len = value_buf.len() as u32;
                    let mut value_type: u32 = 0;

                    let result = RegEnumValueW(
                        key,
                        index,
                        windows::core::PWSTR(name_buf.as_mut_ptr()),
                        &mut name_len,
                        None,
                        Some(&mut value_type),
                        Some(value_buf.as_mut_ptr()),
                        Some(&mut value_len),
                    );

                    if result.is_err() {
                        break;
                    }

                    let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
                    let value = if value_type == REG_SZ.0 {
                        String::from_utf16_lossy(&std::slice::from_raw_parts(
                            value_buf.as_ptr() as *const u16,
                            (value_len as usize) / 2,
                        ))
                    } else {
                        format!("(binary data, type {})", value_type)
                    };

                    values.push((name, value));
                    index += 1;
                }

                let _ = RegCloseKey(key);
            }
        }

        Ok(values)
    }

    #[cfg(target_os = "windows")]
    /// Create service event
    fn create_windows_service_event(service: &WindowsService) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ServiceInstalled);
        event.severity = EventSeverity::Medium;

        event.add_tag("persistence");
        event.add_tag("windows");
        event.add_tag("service");

        // Check for suspicious service patterns
        let suspicious_patterns = vec![
            "backdoor", "reverse", "shell", "netcat", "miner", "crypto",
        ];

        let service_lower = format!("{} {}", service.name, service.path_name).to_lowercase();
        for pattern in suspicious_patterns {
            if service_lower.contains(pattern) {
                event.add_tag("suspicious");
                event.severity = EventSeverity::High;
                event.set_mitre(
                    vec!["Persistence".to_string()],
                    vec!["T1543.003".to_string()], // Windows Service
                );
                break;
            }
        }

        event
    }

    #[cfg(target_os = "windows")]
    /// Create scheduled task event
    fn create_windows_task_event(task: &ScheduledTask) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ScheduledTaskCreated);
        event.severity = EventSeverity::Medium;

        event.add_tag("persistence");
        event.add_tag("windows");
        event.add_tag("scheduled_task");

        event.set_mitre(
            vec!["Persistence".to_string(), "Execution".to_string()],
            vec!["T1053.005".to_string()], // Scheduled Task
        );

        event
    }

    #[cfg(target_os = "windows")]
    /// Create registry autorun event
    fn create_windows_registry_event(autorun: &RegistryAutorun) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::RegistryValueSet);
        event.severity = EventSeverity::Medium;

        event.add_tag("persistence");
        event.add_tag("windows");
        event.add_tag("registry");
        event.add_tag("autorun");

        // Check for suspicious registry autoruns
        let suspicious_patterns = vec![
            "powershell", "cmd.exe", "wscript", "cscript", "rundll32",
            "regsvr32", "mshta", "certutil", "bitsadmin",
        ];

        let value_lower = autorun.value.to_lowercase();
        for pattern in suspicious_patterns {
            if value_lower.contains(pattern) {
                event.add_tag("suspicious");
                event.add_tag("lolbin");
                event.severity = EventSeverity::High;
                event.set_mitre(
                    vec!["Persistence".to_string(), "Defense Evasion".to_string()],
                    vec!["T1547.001".to_string(), "T1218".to_string()], // Registry Run Keys, LOLBins
                );
                break;
            }
        }

        event
    }

    // ===== Stub implementations for non-Linux, non-Windows platforms =====

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_systemd_services() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_systemd_timers() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_cron_files() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn get_autostart_files() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn create_service_event(_service_name: &str) -> SecurityEvent {
        SecurityEvent::new(EventType::ServiceInstalled)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn create_timer_event(_timer_name: &str) -> SecurityEvent {
        SecurityEvent::new(EventType::ScheduledTaskCreated)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn create_cron_event(_cron_file: &str) -> SecurityEvent {
        SecurityEvent::new(EventType::ScheduledTaskCreated)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn create_autostart_event(_autostart_file: &str) -> SecurityEvent {
        SecurityEvent::new(EventType::ServiceInstalled)
    }
}

#[async_trait::async_trait]
impl EventCollector for PersistenceSensor {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running = true;

        #[cfg(target_os = "linux")]
        {
            // Initialize known persistence mechanisms
            let services = Self::get_systemd_services();
            let mut known_services = self.known_services.lock();
            for service in services {
                known_services.insert(service);
            }
            drop(known_services);

            let timers = Self::get_systemd_timers();
            let mut known_timers = self.known_timers.lock();
            for timer in timers {
                known_timers.insert(timer);
            }
            drop(known_timers);

            let cron_files = Self::get_cron_files();
            let mut known_cron = self.known_cron_files.lock();
            for cron_file in cron_files {
                known_cron.insert(cron_file);
            }
            drop(known_cron);

            let autostart_files = Self::get_autostart_files();
            let mut known_autostart = self.known_autostart.lock();
            for autostart_file in autostart_files {
                known_autostart.insert(autostart_file);
            }
            drop(known_autostart);

            // Start background monitoring
            let known_services = Arc::clone(&self.known_services);
            let known_timers = Arc::clone(&self.known_timers);
            let known_cron_files = Arc::clone(&self.known_cron_files);
            let known_autostart = Arc::clone(&self.known_autostart);
            let events = Arc::clone(&self.events);

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

                loop {
                    interval.tick().await;

                    // Check for new services
                    let services = PersistenceSensor::get_systemd_services();
                    let mut known = known_services.lock();
                    for service in services {
                        if !known.contains(&service) {
                            let event = PersistenceSensor::create_service_event(&service);
                            events.lock().push(event);
                            known.insert(service);
                        }
                    }
                    drop(known);

                    // Check for new timers
                    let timers = PersistenceSensor::get_systemd_timers();
                    let mut known = known_timers.lock();
                    for timer in timers {
                        if !known.contains(&timer) {
                            let event = PersistenceSensor::create_timer_event(&timer);
                            events.lock().push(event);
                            known.insert(timer);
                        }
                    }
                    drop(known);

                    // Check for new cron files
                    let cron_files = PersistenceSensor::get_cron_files();
                    let mut known = known_cron_files.lock();
                    for cron_file in cron_files {
                        if !known.contains(&cron_file) {
                            let event = PersistenceSensor::create_cron_event(&cron_file);
                            events.lock().push(event);
                            known.insert(cron_file);
                        }
                    }
                    drop(known);

                    // Check for new autostart files
                    let autostart_files = PersistenceSensor::get_autostart_files();
                    let mut known = known_autostart.lock();
                    for autostart_file in autostart_files {
                        if !known.contains(&autostart_file) {
                            let event = PersistenceSensor::create_autostart_event(&autostart_file);
                            events.lock().push(event);
                            known.insert(autostart_file);
                        }
                    }
                }
            });
        }

        #[cfg(target_os = "windows")]
        {
            // Initialize known Windows persistence mechanisms
            let services = Self::get_windows_services();
            let mut known_services = self.known_services.lock();
            for service in services {
                known_services.insert(service.name.clone());
            }
            drop(known_services);

            let tasks = Self::get_scheduled_tasks();
            let mut known_tasks = self.known_timers.lock(); // Reuse timers field for Windows tasks
            for task in tasks {
                known_tasks.insert(task.name.clone());
            }
            drop(known_tasks);

            let autoruns = Self::get_registry_autoruns();
            let mut known_autoruns = self.known_autostart.lock(); // Reuse autostart field for registry
            for autorun in autoruns {
                let key = format!("{}\\{}\\{}", autorun.hive, autorun.key, autorun.name);
                known_autoruns.insert(key);
            }
            drop(known_autoruns);

            // Start background monitoring for Windows
            let known_services = Arc::clone(&self.known_services);
            let known_tasks = Arc::clone(&self.known_timers);
            let known_autoruns = Arc::clone(&self.known_autostart);
            let events = Arc::clone(&self.events);

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

                loop {
                    interval.tick().await;

                    // Check for new Windows services
                    let services = PersistenceSensor::get_windows_services();
                    let mut known = known_services.lock();
                    for service in services {
                        if !known.contains(&service.name) {
                            let event = PersistenceSensor::create_windows_service_event(&service);
                            events.lock().push(event);
                            known.insert(service.name);
                        }
                    }
                    drop(known);

                    // Check for new scheduled tasks
                    let tasks = PersistenceSensor::get_scheduled_tasks();
                    let mut known = known_tasks.lock();
                    for task in tasks {
                        if !known.contains(&task.name) {
                            let event = PersistenceSensor::create_windows_task_event(&task);
                            events.lock().push(event);
                            known.insert(task.name);
                        }
                    }
                    drop(known);

                    // Check for new registry autoruns
                    let autoruns = PersistenceSensor::get_registry_autoruns();
                    let mut known = known_autoruns.lock();
                    for autorun in autoruns {
                        let key = format!("{}\\{}\\{}", autorun.hive, autorun.key, autorun.name);
                        if !known.contains(&key) {
                            let event = PersistenceSensor::create_windows_registry_event(&autorun);
                            events.lock().push(event);
                            known.insert(key);
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

// Windows-specific structs
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct WindowsService {
    name: String,
    display_name: String,
    state: String,
    start_mode: String,
    path_name: String,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct ScheduledTask {
    name: String,
    enabled: String,
    state: String,
    author: String,
}

#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
struct RegistryAutorun {
    hive: String,
    key: String,
    name: String,
    value: String,
}
