// Event Collection & Sensor Framework
// Common schema for all security events (Sigma-compatible)

pub mod events;
pub mod process_sensor;
pub mod file_sensor;
pub mod network_sensor;
pub mod identity_sensor;
pub mod persistence_sensor;
pub mod package_sensor;

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

pub use events::*;
pub use process_sensor::ProcessSensor;
pub use file_sensor::FileSensor;
pub use network_sensor::NetworkSensor;
pub use identity_sensor::IdentitySensor;
pub use persistence_sensor::PersistenceSensor;
pub use package_sensor::PackageSensor;

/// Unified Security Event - Sigma-like schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event ID
    pub id: String,

    /// Event timestamp
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: EventType,

    /// Operating system
    pub os: OperatingSystem,

    /// Hostname/device name
    pub hostname: String,

    /// Event severity
    pub severity: EventSeverity,

    /// Process context
    pub process: Option<ProcessContext>,

    /// File context
    pub file: Option<FileContext>,

    /// Network context
    pub network: Option<NetworkContext>,

    /// Identity context
    pub identity: Option<IdentityContext>,

    /// Registry context (Windows)
    pub registry: Option<RegistryContext>,

    /// Raw event data (OS-specific)
    pub raw_data: HashMap<String, String>,

    /// Tags for correlation
    pub tags: Vec<String>,

    /// MITRE ATT&CK mapping
    pub mitre_attack: Option<MitreAttackMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventType {
    // Process events
    ProcessCreated,
    ProcessTerminated,
    ProcessAccess,

    // File events
    FileCreated,
    FileModified,
    FileDeleted,
    FileRenamed,
    FileAccessed,

    // Network events
    NetworkConnection,
    NetworkDNSQuery,
    NetworkListen,

    // Identity events
    UserLogon,
    UserLogoff,
    UserCreated,
    UserDeleted,
    UserModified,
    GroupModified,
    PrivilegeEscalation,

    // Persistence events
    ServiceInstalled,
    ServiceModified,
    ScheduledTaskCreated,
    ScheduledTaskModified,
    AutorunCreated,
    AutorunModified,

    // Registry events (Windows)
    RegistryKeyCreated,
    RegistryKeyModified,
    RegistryKeyDeleted,
    RegistryValueSet,

    // Driver events
    DriverLoaded,

    // Other
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OperatingSystem {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Process context for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_name: Option<String>,
    pub parent_path: Option<String>,
    pub user: Option<String>,
    pub integrity_level: Option<String>,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,
    pub signer: Option<String>,
    pub signed: Option<bool>,
}

/// File context for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    pub path: String,
    pub name: String,
    pub extension: Option<String>,
    pub size: Option<u64>,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,
    pub created_time: Option<DateTime<Utc>>,
    pub modified_time: Option<DateTime<Utc>>,
    pub accessed_time: Option<DateTime<Utc>>,
    pub attributes: Option<String>,
    pub owner: Option<String>,
    pub permissions: Option<String>,
}

/// Network context for events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub source_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
    pub direction: NetworkDirection,
    pub dns_query: Option<String>,
    pub dns_response: Option<Vec<String>>,
    pub ja3_hash: Option<String>,
    pub sni: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkDirection {
    Inbound,
    Outbound,
    Lateral,
}

/// Identity/authentication context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityContext {
    pub user: String,
    pub domain: Option<String>,
    pub logon_type: Option<String>,
    pub logon_id: Option<String>,
    pub source_workstation: Option<String>,
    pub source_ip: Option<String>,
    pub elevated: Option<bool>,
    pub privileges: Option<Vec<String>>,
}

/// Windows Registry context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryContext {
    pub key_path: String,
    pub value_name: Option<String>,
    pub value_data: Option<String>,
    pub value_type: Option<String>,
}

/// MITRE ATT&CK mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreAttackMapping {
    pub tactics: Vec<String>,
    pub techniques: Vec<String>,
    pub sub_techniques: Vec<String>,
}

/// Event collector trait - implemented by all sensors
#[async_trait::async_trait]
pub trait EventCollector: Send + Sync {
    /// Start collecting events
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>>;

    /// Stop collecting events
    async fn stop(&mut self);

    /// Get collected events
    async fn collect_events(&mut self) -> Vec<SecurityEvent>;

    /// Check if sensor is running
    fn is_running(&self) -> bool;
}

/// Event normalizer - converts OS-specific events to SecurityEvent
pub trait EventNormalizer {
    fn normalize(&self, raw_event: &dyn std::any::Any) -> Option<SecurityEvent>;
}

/// Sensor manager - coordinates all sensors
pub struct SensorManager {
    process_sensor: Option<ProcessSensor>,
    file_sensor: Option<FileSensor>,
    network_sensor: Option<NetworkSensor>,
    identity_sensor: Option<IdentitySensor>,
    persistence_sensor: Option<PersistenceSensor>,
    running: bool,
}

impl SensorManager {
    pub fn new() -> Self {
        Self {
            process_sensor: None,
            file_sensor: None,
            network_sensor: None,
            identity_sensor: None,
            persistence_sensor: None,
            running: false,
        }
    }

    /// Initialize all sensors for the current OS
    pub async fn initialize(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        #[cfg(target_os = "linux")]
        {
            self.process_sensor = Some(ProcessSensor::new_linux()?);
            self.file_sensor = Some(FileSensor::new_linux()?);
            self.network_sensor = Some(NetworkSensor::new_linux()?);
            self.identity_sensor = Some(IdentitySensor::new_linux()?);
            self.persistence_sensor = Some(PersistenceSensor::new_linux()?);
        }

        #[cfg(target_os = "windows")]
        {
            self.process_sensor = Some(ProcessSensor::new_windows()?);
            self.file_sensor = Some(FileSensor::new_windows()?);
            self.network_sensor = Some(NetworkSensor::new_windows()?);
            self.identity_sensor = Some(IdentitySensor::new_windows()?);
            self.persistence_sensor = Some(PersistenceSensor::new_windows()?);
        }

        #[cfg(target_os = "macos")]
        {
            self.process_sensor = Some(ProcessSensor::new_macos()?);
            self.file_sensor = Some(FileSensor::new_macos()?);
            self.network_sensor = Some(NetworkSensor::new_macos()?);
            self.identity_sensor = Some(IdentitySensor::new_macos()?);
            self.persistence_sensor = Some(PersistenceSensor::new_macos()?);
        }

        Ok(())
    }

    /// Start all sensors
    pub async fn start_all(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(sensor) = &mut self.process_sensor {
            sensor.start().await?;
        }

        if let Some(sensor) = &mut self.file_sensor {
            sensor.start().await?;
        }

        if let Some(sensor) = &mut self.network_sensor {
            sensor.start().await?;
        }

        if let Some(sensor) = &mut self.identity_sensor {
            sensor.start().await?;
        }

        if let Some(sensor) = &mut self.persistence_sensor {
            sensor.start().await?;
        }

        self.running = true;
        Ok(())
    }

    /// Stop all sensors
    pub async fn stop_all(&mut self) {
        if let Some(sensor) = &mut self.process_sensor {
            sensor.stop().await;
        }

        if let Some(sensor) = &mut self.file_sensor {
            sensor.stop().await;
        }

        if let Some(sensor) = &mut self.network_sensor {
            sensor.stop().await;
        }

        if let Some(sensor) = &mut self.identity_sensor {
            sensor.stop().await;
        }

        if let Some(sensor) = &mut self.persistence_sensor {
            sensor.stop().await;
        }

        self.running = false;
    }

    /// Collect events from all sensors
    pub async fn collect_all_events(&mut self) -> Vec<SecurityEvent> {
        let mut all_events = Vec::new();

        if let Some(sensor) = &mut self.process_sensor {
            all_events.extend(sensor.collect_events().await);
        }

        if let Some(sensor) = &mut self.file_sensor {
            all_events.extend(sensor.collect_events().await);
        }

        if let Some(sensor) = &mut self.network_sensor {
            all_events.extend(sensor.collect_events().await);
        }

        if let Some(sensor) = &mut self.identity_sensor {
            all_events.extend(sensor.collect_events().await);
        }

        if let Some(sensor) = &mut self.persistence_sensor {
            all_events.extend(sensor.collect_events().await);
        }

        all_events
    }

    pub fn is_running(&self) -> bool {
        self.running
    }
}

impl Default for SensorManager {
    fn default() -> Self {
        Self::new()
    }
}
