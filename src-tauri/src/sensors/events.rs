// Event utility functions

use super::*;

impl SecurityEvent {
    /// Create a new security event
    pub fn new(event_type: EventType) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            os: get_current_os(),
            hostname: get_hostname(),
            severity: EventSeverity::Info,
            process: None,
            file: None,
            network: None,
            identity: None,
            registry: None,
            raw_data: HashMap::new(),
            tags: Vec::new(),
            mitre_attack: None,
        }
    }

    /// Add tag to event
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Set MITRE ATT&CK mapping
    pub fn set_mitre(&mut self, tactics: Vec<String>, techniques: Vec<String>) {
        self.mitre_attack = Some(MitreAttackMapping {
            tactics,
            techniques,
            sub_techniques: Vec::new(),
        });
    }

    /// Check if event matches sensitive patterns
    pub fn is_suspicious(&self) -> bool {
        // Check for suspicious process names
        if let Some(proc) = &self.process {
            let suspicious_names = [
                "mimikatz", "psexec", "procdump", "pwdump",
                "powershell", "cmd", "wmic", "mshta",
            ];

            let name_lower = proc.name.to_lowercase();
            if suspicious_names.iter().any(|&s| name_lower.contains(s)) {
                return true;
            }

            // Check for suspicious paths
            if proc.path.contains("\\Temp\\") ||
               proc.path.contains("/tmp/") ||
               proc.path.contains("\\AppData\\Local\\Temp") {
                return true;
            }
        }

        // Check for suspicious file operations
        if let Some(file) = &self.file {
            let suspicious_extensions = [
                ".exe", ".dll", ".bat", ".ps1", ".vbs", ".js",
                ".scr", ".com", ".pif",
            ];

            if let Some(ext) = &file.extension {
                if suspicious_extensions.contains(&ext.as_str()) {
                    return true;
                }
            }

            // Check for sensitive paths
            if file.path.contains("System32\\config") ||
               file.path.contains("/etc/shadow") ||
               file.path.contains("/etc/passwd") {
                return true;
            }
        }

        false
    }
}

/// Get current operating system
pub fn get_current_os() -> OperatingSystem {
    #[cfg(target_os = "windows")]
    return OperatingSystem::Windows;

    #[cfg(target_os = "linux")]
    return OperatingSystem::Linux;

    #[cfg(target_os = "macos")]
    return OperatingSystem::MacOS;

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return OperatingSystem::Unknown;
}

/// Get hostname
pub fn get_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Calculate file hash (SHA256)
pub fn calculate_file_hash(path: &std::path::Path) -> Option<String> {
    use sha2::{Sha256, Digest};
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Some(format!("{:x}", hasher.finalize()))
}
