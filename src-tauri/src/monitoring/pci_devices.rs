use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{info, warn, error};

#[derive(Error, Debug)]
pub enum PciError {
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("Failed to read PCI data: {0}")]
    ReadError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PciDevice {
    /// PCI address (e.g., "0000:00:00.0")
    pub address: String,
    /// Vendor ID (hex)
    pub vendor_id: String,
    /// Device ID (hex)
    pub device_id: String,
    /// Vendor name (if known)
    pub vendor_name: Option<String>,
    /// Device name (if known)
    pub device_name: Option<String>,
    /// Device class (e.g., "Network controller")
    pub device_class: String,
    /// Device subclass
    pub device_subclass: String,
    /// Subsystem vendor ID
    pub subsystem_vendor_id: Option<String>,
    /// Subsystem device ID
    pub subsystem_device_id: Option<String>,
    /// Driver in use (if any)
    pub driver: Option<String>,
    /// IOMMU group (for virtualization/security)
    pub iommu_group: Option<String>,
    /// Is this device enabled?
    pub enabled: bool,
}

pub struct PciEnumerator;

impl PciEnumerator {
    pub fn new() -> Self {
        Self
    }

    /// Enumerate all PCI devices on the system
    pub fn enumerate_devices() -> Result<Vec<PciDevice>, PciError> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                Self::enumerate_linux()
            } else if #[cfg(target_os = "windows")] {
                Self::enumerate_windows()
            } else {
                Err(PciError::UnsupportedPlatform(
                    std::env::consts::OS.to_string()
                ))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn enumerate_linux() -> Result<Vec<PciDevice>, PciError> {
        use std::fs;
        use std::path::Path;

        let mut devices = Vec::new();
        let pci_path = Path::new("/sys/bus/pci/devices");

        if !pci_path.exists() {
            return Err(PciError::ReadError(
                "PCI sysfs path not found".to_string()
            ));
        }

        // Read all PCI device directories
        let entries = fs::read_dir(pci_path)
            .map_err(|e| PciError::ReadError(format!("Failed to read PCI directory: {}", e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| PciError::ReadError(format!("Failed to read entry: {}", e)))?;
            let path = entry.path();
            let address = entry.file_name().to_string_lossy().to_string();

            // Read vendor and device IDs
            let vendor_id = Self::read_hex_file(&path.join("vendor"))
                .unwrap_or_else(|| "unknown".to_string());
            let device_id = Self::read_hex_file(&path.join("device"))
                .unwrap_or_else(|| "unknown".to_string());

            // Read class information
            let class_id = Self::read_hex_file(&path.join("class"))
                .unwrap_or_else(|| "0x000000".to_string());
            let (device_class, device_subclass) = Self::parse_class_code(&class_id);

            // Read subsystem IDs
            let subsystem_vendor_id = Self::read_hex_file(&path.join("subsystem_vendor"));
            let subsystem_device_id = Self::read_hex_file(&path.join("subsystem_device"));

            // Read driver information
            let driver = Self::read_driver(&path);

            // Read IOMMU group
            let iommu_group = Self::read_iommu_group(&path);

            // Check if device is enabled
            let enabled = Self::read_hex_file(&path.join("enable"))
                .map(|e| e != "0x0")
                .unwrap_or(true);

            // Lookup vendor and device names
            let (vendor_name, device_name) = Self::lookup_pci_names(&vendor_id, &device_id);

            devices.push(PciDevice {
                address,
                vendor_id,
                device_id,
                vendor_name,
                device_name,
                device_class,
                device_subclass,
                subsystem_vendor_id,
                subsystem_device_id,
                driver,
                iommu_group,
                enabled,
            });
        }

        info!("Enumerated {} PCI devices", devices.len());
        Ok(devices)
    }

    #[cfg(target_os = "windows")]
    fn enumerate_windows() -> Result<Vec<PciDevice>, PciError> {
        use std::process::Command;

        // Use PowerShell to query WMI for PCI devices
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                r#"Get-WmiObject Win32_PnPEntity | Where-Object {$_.DeviceID -like 'PCI*'} | Select-Object DeviceID, Name, Status, Manufacturer | ConvertTo-Json"#
            ])
            .output()
            .map_err(|e| PciError::ReadError(format!("Failed to execute PowerShell: {}", e)))?;

        if !output.status.success() {
            return Err(PciError::ReadError(
                format!("PowerShell command failed: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }

        let json_str = String::from_utf8_lossy(&output.stdout);

        // Parse JSON output
        let devices = Self::parse_windows_wmi_json(&json_str)?;

        info!("Enumerated {} PCI devices on Windows", devices.len());
        Ok(devices)
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_wmi_json(json_str: &str) -> Result<Vec<PciDevice>, PciError> {
        use std::collections::HashMap;

        let mut devices = Vec::new();

        // Simple JSON parsing (would be better with serde_json, but keeping dependencies minimal)
        // For now, parse the basic structure manually or use a simple approach

        // Try to parse as array first, then single object
        if json_str.trim().is_empty() || json_str.trim() == "null" {
            return Ok(devices);
        }

        // This is a simplified parser - in production, use serde_json
        // For now, just extract basic info using regex-like parsing
        for line in json_str.lines() {
            if line.contains("DeviceID") {
                // Extract basic device info
                // Format: PCI\VEN_XXXX&DEV_YYYY&...
                if let Some(device_id_start) = line.find("PCI\\") {
                    if let Some(device_id_end) = line[device_id_start..].find('"') {
                        let device_id = &line[device_id_start..device_id_start + device_id_end];

                        let (vendor_id, dev_id) = Self::parse_windows_device_id(device_id);

                        devices.push(PciDevice {
                            address: device_id.to_string(),
                            vendor_id: vendor_id.clone(),
                            device_id: dev_id.clone(),
                            vendor_name: Self::lookup_pci_names(&vendor_id, &dev_id).0,
                            device_name: None,
                            device_class: "Unknown".to_string(),
                            device_subclass: "Unknown".to_string(),
                            subsystem_vendor_id: None,
                            subsystem_device_id: None,
                            driver: None,
                            iommu_group: None,
                            enabled: true, // Assume enabled if listed by WMI
                        });
                    }
                }
            }
        }

        Ok(devices)
    }

    #[cfg(target_os = "windows")]
    fn parse_windows_device_id(device_id: &str) -> (String, String) {
        // Parse Windows device ID format: PCI\VEN_XXXX&DEV_YYYY&...
        let mut vendor_id = "unknown".to_string();
        let mut dev_id = "unknown".to_string();

        if let Some(ven_pos) = device_id.find("VEN_") {
            let ven_str = &device_id[ven_pos + 4..];
            if let Some(end) = ven_str.find('&') {
                vendor_id = format!("0x{}", &ven_str[..end]);
            } else if ven_str.len() >= 4 {
                vendor_id = format!("0x{}", &ven_str[..4]);
            }
        }

        if let Some(dev_pos) = device_id.find("DEV_") {
            let dev_str = &device_id[dev_pos + 4..];
            if let Some(end) = dev_str.find('&') {
                dev_id = format!("0x{}", &dev_str[..end]);
            } else if dev_str.len() >= 4 {
                dev_id = format!("0x{}", &dev_str[..4]);
            }
        }

        (vendor_id, dev_id)
    }

    #[cfg(target_os = "linux")]
    fn read_hex_file(path: &std::path::Path) -> Option<String> {
        std::fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
    }

    #[cfg(target_os = "linux")]
    fn read_driver(device_path: &std::path::Path) -> Option<String> {
        let driver_link = device_path.join("driver");
        if let Ok(target) = std::fs::read_link(&driver_link) {
            target
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn read_iommu_group(device_path: &std::path::Path) -> Option<String> {
        let iommu_link = device_path.join("iommu_group");
        if let Ok(target) = std::fs::read_link(&iommu_link) {
            target
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.to_string())
        } else {
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_class_code(class_hex: &str) -> (String, String) {
        // Class code format: 0xCCSSPP (Class, Subclass, Programming Interface)
        let class_num = u32::from_str_radix(class_hex.trim_start_matches("0x"), 16)
            .unwrap_or(0);

        let class = (class_num >> 16) & 0xFF;
        let subclass = (class_num >> 8) & 0xFF;

        let class_name = Self::get_class_name(class as u8);
        let subclass_name = Self::get_subclass_name(class as u8, subclass as u8);

        (class_name, subclass_name)
    }

    fn get_class_name(class: u8) -> String {
        match class {
            0x00 => "Unclassified".to_string(),
            0x01 => "Mass Storage Controller".to_string(),
            0x02 => "Network Controller".to_string(),
            0x03 => "Display Controller".to_string(),
            0x04 => "Multimedia Controller".to_string(),
            0x05 => "Memory Controller".to_string(),
            0x06 => "Bridge Device".to_string(),
            0x07 => "Simple Communication Controller".to_string(),
            0x08 => "Base System Peripheral".to_string(),
            0x09 => "Input Device".to_string(),
            0x0A => "Docking Station".to_string(),
            0x0B => "Processor".to_string(),
            0x0C => "Serial Bus Controller".to_string(),
            0x0D => "Wireless Controller".to_string(),
            0x0E => "Intelligent I/O Controller".to_string(),
            0x0F => "Satellite Communication Controller".to_string(),
            0x10 => "Encryption/Decryption Controller".to_string(),
            0x11 => "Data Acquisition Controller".to_string(),
            _ => format!("Unknown Class (0x{:02X})", class),
        }
    }

    fn get_subclass_name(class: u8, subclass: u8) -> String {
        match (class, subclass) {
            (0x02, 0x00) => "Ethernet Controller".to_string(),
            (0x02, 0x80) => "Other Network Controller".to_string(),
            (0x03, 0x00) => "VGA Compatible Controller".to_string(),
            (0x03, 0x01) => "XGA Controller".to_string(),
            (0x03, 0x02) => "3D Controller".to_string(),
            (0x06, 0x00) => "Host Bridge".to_string(),
            (0x06, 0x01) => "ISA Bridge".to_string(),
            (0x06, 0x04) => "PCI-to-PCI Bridge".to_string(),
            (0x0C, 0x03) => "USB Controller".to_string(),
            _ => format!("Subclass 0x{:02X}", subclass),
        }
    }

    fn lookup_pci_names(vendor_id: &str, device_id: &str) -> (Option<String>, Option<String>) {
        // Common vendor IDs
        let vendor_name = match vendor_id {
            "0x8086" => Some("Intel Corporation"),
            "0x10de" => Some("NVIDIA Corporation"),
            "0x1002" => Some("Advanced Micro Devices, Inc. [AMD/ATI]"),
            "0x1022" => Some("Advanced Micro Devices, Inc. [AMD]"),
            "0x14e4" => Some("Broadcom Inc."),
            "0x8086" => Some("Intel Corporation"),
            "0x10ec" => Some("Realtek Semiconductor Co., Ltd."),
            "0x1af4" => Some("Red Hat, Inc."),
            "0x15ad" => Some("VMware"),
            "0x1234" => Some("QEMU"),
            _ => None,
        }.map(|s| s.to_string());

        // Device names would require a full PCI ID database
        // For now, return None for device names
        let device_name = None;

        (vendor_name, device_name)
    }
}
