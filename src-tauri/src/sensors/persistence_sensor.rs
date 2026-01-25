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

    #[cfg(not(target_os = "linux"))]
    fn get_systemd_services() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(target_os = "linux"))]
    fn get_systemd_timers() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(target_os = "linux"))]
    fn get_cron_files() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(target_os = "linux"))]
    fn get_autostart_files() -> Vec<String> {
        Vec::new()
    }

    #[cfg(not(target_os = "linux"))]
    fn create_service_event(_service_name: &str) -> SecurityEvent {
        SecurityEvent::new(EventType::ServiceInstalled)
    }

    #[cfg(not(target_os = "linux"))]
    fn create_timer_event(_timer_name: &str) -> SecurityEvent {
        SecurityEvent::new(EventType::ScheduledTaskCreated)
    }

    #[cfg(not(target_os = "linux"))]
    fn create_cron_event(_cron_file: &str) -> SecurityEvent {
        SecurityEvent::new(EventType::ScheduledTaskCreated)
    }

    #[cfg(not(target_os = "linux"))]
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
