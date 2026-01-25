use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn, error};

#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Failed to read security data: {0}")]
    ReadError(String),
    #[error("TPM not available: {0}")]
    TpmNotAvailable(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSecurityStatus {
    /// TPM (Trusted Platform Module) status
    pub tpm: TpmStatus,
    /// Secure Boot status
    pub secure_boot: SecureBootStatus,
    /// UEFI/BIOS information
    pub firmware: FirmwareInfo,
    /// Measured Boot / Boot Integrity
    pub boot_integrity: BootIntegrityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmStatus {
    /// Is TPM present?
    pub present: bool,
    /// TPM version (1.2 or 2.0)
    pub version: Option<String>,
    /// Is TPM enabled?
    pub enabled: bool,
    /// Is TPM activated?
    pub activated: bool,
    /// Is TPM owned?
    pub owned: bool,
    /// Manufacturer ID
    pub manufacturer: Option<String>,
    /// Firmware version
    pub firmware_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureBootStatus {
    /// Is Secure Boot enabled?
    pub enabled: bool,
    /// Is Secure Boot policy active?
    pub policy_active: bool,
    /// Setup Mode (true = can modify keys)
    pub setup_mode: bool,
    /// Signature database (db) count
    pub db_signature_count: Option<u32>,
    /// Forbidden signature database (dbx) count
    pub dbx_signature_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareInfo {
    /// Firmware type (UEFI, BIOS, etc.)
    pub firmware_type: String,
    /// Firmware vendor
    pub vendor: Option<String>,
    /// Firmware version
    pub version: Option<String>,
    /// Release date
    pub release_date: Option<String>,
    /// Is this a legacy BIOS?
    pub is_legacy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootIntegrityStatus {
    /// Are boot measurements available?
    pub measurements_available: bool,
    /// Number of PCR (Platform Configuration Register) values
    pub pcr_count: u8,
    /// PCR values (if available)
    pub pcr_values: Vec<PcrValue>,
    /// Boot chain integrity status
    pub integrity_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrValue {
    /// PCR index (0-23)
    pub index: u8,
    /// PCR value (hash)
    pub value: String,
    /// Algorithm used (SHA1, SHA256, etc.)
    pub algorithm: String,
}

pub struct PlatformSecurityMonitor;

impl PlatformSecurityMonitor {
    pub fn new() -> Self {
        Self
    }

    /// Get complete platform security status
    pub fn get_security_status() -> Result<PlatformSecurityStatus, SecurityError> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                Self::get_linux_security_status()
            } else if #[cfg(target_os = "windows")] {
                Self::get_windows_security_status()
            } else {
                Err(SecurityError::UnsupportedPlatform(
                    std::env::consts::OS.to_string()
                ))
            }
        }
    }

    // ==================== LINUX IMPLEMENTATION ====================

    #[cfg(target_os = "linux")]
    fn get_linux_security_status() -> Result<PlatformSecurityStatus, SecurityError> {
        let tpm = Self::read_linux_tpm_status();
        let secure_boot = Self::read_linux_secure_boot();
        let firmware = Self::read_linux_firmware_info();
        let boot_integrity = Self::read_linux_boot_integrity();

        Ok(PlatformSecurityStatus {
            tpm,
            secure_boot,
            firmware,
            boot_integrity,
        })
    }

    #[cfg(target_os = "linux")]
    fn read_linux_tpm_status() -> TpmStatus {
        use std::path::Path;
        use std::fs;

        // Check if TPM is present via /sys/class/tpm
        let tpm_path = Path::new("/sys/class/tpm/tpm0");
        let present = tpm_path.exists();

        if !present {
            return TpmStatus {
                present: false,
                version: None,
                enabled: false,
                activated: false,
                owned: false,
                manufacturer: None,
                firmware_version: None,
            };
        }

        // Read TPM version
        let version = fs::read_to_string(tpm_path.join("tpm_version_major"))
            .ok()
            .and_then(|v| {
                let major = v.trim().parse::<u8>().ok()?;
                Some(format!("{}.0", major))
            });

        // Read device information
        let device_manufacturer = fs::read_to_string(tpm_path.join("device/manufacturer"))
            .ok()
            .map(|s| s.trim().to_string());

        let firmware_version = fs::read_to_string(tpm_path.join("device/firmware_version"))
            .ok()
            .map(|s| s.trim().to_string());

        // Check if TPM is enabled/owned (requires tpm2-tools)
        let (enabled, activated, owned) = Self::check_tpm2_status();

        TpmStatus {
            present,
            version,
            enabled,
            activated,
            owned,
            manufacturer: device_manufacturer,
            firmware_version,
        }
    }

    #[cfg(target_os = "linux")]
    fn check_tpm2_status() -> (bool, bool, bool) {
        use std::process::Command;

        // Try to use tpm2_getcap if available
        if let Ok(output) = Command::new("tpm2_getcap")
            .args(&["properties-fixed"])
            .output()
        {
            if output.status.success() {
                // If command succeeds, TPM is enabled and activated
                return (true, true, true);
            }
        }

        // Fallback: assume enabled if device exists
        (true, true, false)
    }

    #[cfg(target_os = "linux")]
    fn read_linux_secure_boot() -> SecureBootStatus {
        use std::fs;

        // Read Secure Boot status from UEFI variables
        let enabled = fs::read_to_string("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
            .ok()
            .and_then(|content| {
                // UEFI variable format: 4-byte attributes + data
                content.as_bytes().get(4).copied()
            })
            .map(|byte| byte == 1)
            .unwrap_or(false);

        let setup_mode = fs::read_to_string("/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c")
            .ok()
            .and_then(|content| content.as_bytes().get(4).copied())
            .map(|byte| byte == 1)
            .unwrap_or(false);

        SecureBootStatus {
            enabled,
            policy_active: enabled && !setup_mode,
            setup_mode,
            db_signature_count: None, // Would require parsing EFI signature database
            dbx_signature_count: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn read_linux_firmware_info() -> FirmwareInfo {
        use std::fs;
        use std::path::Path;

        let is_uefi = Path::new("/sys/firmware/efi").exists();

        let vendor = fs::read_to_string("/sys/class/dmi/id/bios_vendor")
            .ok()
            .map(|s| s.trim().to_string());

        let version = fs::read_to_string("/sys/class/dmi/id/bios_version")
            .ok()
            .map(|s| s.trim().to_string());

        let release_date = fs::read_to_string("/sys/class/dmi/id/bios_date")
            .ok()
            .map(|s| s.trim().to_string());

        FirmwareInfo {
            firmware_type: if is_uefi { "UEFI".to_string() } else { "BIOS".to_string() },
            vendor,
            version,
            release_date,
            is_legacy: !is_uefi,
        }
    }

    #[cfg(target_os = "linux")]
    fn read_linux_boot_integrity() -> BootIntegrityStatus {
        use std::fs;
        use std::path::Path;

        let tpm_path = Path::new("/sys/class/tpm/tpm0");
        let measurements_available = tpm_path.exists();

        let mut pcr_values = Vec::new();

        if measurements_available {
            // Read PCR values from /sys/class/tpm/tpm0/pcr-sha256/ (for TPM 2.0)
            let pcr_dir = tpm_path.join("pcr-sha256");
            if pcr_dir.exists() {
                for i in 0..24u8 {
                    let pcr_file = pcr_dir.join(format!("{}", i));
                    if let Ok(value) = fs::read_to_string(&pcr_file) {
                        pcr_values.push(PcrValue {
                            index: i,
                            value: value.trim().to_string(),
                            algorithm: "SHA256".to_string(),
                        });
                    }
                }
            }
        }

        BootIntegrityStatus {
            measurements_available,
            pcr_count: pcr_values.len() as u8,
            pcr_values,
            integrity_verified: measurements_available, // Simplified check
        }
    }

    // ==================== WINDOWS IMPLEMENTATION ====================

    #[cfg(target_os = "windows")]
    fn get_windows_security_status() -> Result<PlatformSecurityStatus, SecurityError> {
        let tpm = Self::read_windows_tpm_status();
        let secure_boot = Self::read_windows_secure_boot();
        let firmware = Self::read_windows_firmware_info();
        let boot_integrity = Self::read_windows_boot_integrity();

        Ok(PlatformSecurityStatus {
            tpm,
            secure_boot,
            firmware,
            boot_integrity,
        })
    }

    #[cfg(target_os = "windows")]
    fn read_windows_tpm_status() -> TpmStatus {
        use std::process::Command;

        // Use PowerShell to query TPM
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                "Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, TpmOwned, ManufacturerId, ManufacturerVersion | ConvertTo-Json"
            ])
            .output();

        if let Ok(result) = output {
            if result.status.success() {
                let json_str = String::from_utf8_lossy(&result.stdout);
                return Self::parse_windows_tpm_json(&json_str);
            }
        }

        // Fallback: empty status
        TpmStatus {
            present: false,
            version: None,
            enabled: false,
            activated: false,
            owned: false,
            manufacturer: None,
            firmware_version: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_tpm_json(json_str: &str) -> TpmStatus {
        // Simplified JSON parsing
        let present = json_str.contains("\"TpmPresent\"") && json_str.contains("true");
        let enabled = json_str.contains("\"TpmEnabled\"") && json_str.contains("true");
        let activated = json_str.contains("\"TpmActivated\"") && json_str.contains("true");
        let owned = json_str.contains("\"TpmOwned\"") && json_str.contains("true");

        TpmStatus {
            present,
            version: Some("2.0".to_string()), // Windows typically uses TPM 2.0
            enabled,
            activated,
            owned,
            manufacturer: None, // Could parse from ManufacturerId
            firmware_version: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn read_windows_secure_boot() -> SecureBootStatus {
        use std::process::Command;

        let enabled = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                "Confirm-SecureBootUEFI"
            ])
            .output()
            .ok()
            .map(|output| output.status.success())
            .unwrap_or(false);

        SecureBootStatus {
            enabled,
            policy_active: enabled,
            setup_mode: false, // Windows doesn't expose this easily
            db_signature_count: None,
            dbx_signature_count: None,
        }
    }

    #[cfg(target_os = "windows")]
    fn read_windows_firmware_info() -> FirmwareInfo {
        use std::process::Command;

        let mut vendor = None;
        let mut version = None;
        let mut release_date = None;

        // Query BIOS information via WMI
        if let Ok(output) = Command::new("wmic")
            .args(&["bios", "get", "Manufacturer,SMBIOSBIOSVersion,ReleaseDate", "/value"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);

            for line in output_str.lines() {
                if line.starts_with("Manufacturer=") {
                    vendor = line.split('=').nth(1).map(|s| s.trim().to_string());
                } else if line.starts_with("SMBIOSBIOSVersion=") {
                    version = line.split('=').nth(1).map(|s| s.trim().to_string());
                } else if line.starts_with("ReleaseDate=") {
                    release_date = line.split('=').nth(1).map(|s| s.trim().to_string());
                }
            }
        }

        // Check if UEFI
        let is_uefi = std::path::Path::new("C:\\Windows\\Panther\\setupact.log").exists(); // Simplified check

        FirmwareInfo {
            firmware_type: if is_uefi { "UEFI".to_string() } else { "BIOS".to_string() },
            vendor,
            version,
            release_date,
            is_legacy: !is_uefi,
        }
    }

    #[cfg(target_os = "windows")]
    fn read_windows_boot_integrity() -> BootIntegrityStatus {
        use std::process::Command;

        // Try to read PCR values using PowerShell
        let mut pcr_values = Vec::new();

        // Windows doesn't easily expose PCR values without admin tools
        // This is a simplified implementation

        BootIntegrityStatus {
            measurements_available: false, // Would need admin privileges
            pcr_count: 0,
            pcr_values,
            integrity_verified: false,
        }
    }
}
