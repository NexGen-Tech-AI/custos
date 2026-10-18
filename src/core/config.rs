use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use config::{Config, ConfigError, File, FileFormat};
use directories::ProjectDirs;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct AppConfig {
    pub monitoring: MonitoringConfig,
    pub alerts: AlertConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub ui: UiConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub cpu: MonitorSettings,
    pub memory: MonitorSettings,
    pub gpu: MonitorSettings,
    pub disk: MonitorSettings,
    pub network: MonitorSettings,
    pub process: ProcessMonitorSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSettings {
    pub enabled: bool,
    pub interval_ms: u64,
    pub retain_history_seconds: u64,
    pub warning_threshold: Option<f32>,
    pub critical_threshold: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMonitorSettings {
    pub enabled: bool,
    pub interval_ms: u64,
    pub top_processes_count: usize,
    pub min_cpu_percent: f32,
    pub min_memory_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    pub enabled: bool,
    pub email: Option<EmailAlertConfig>,
    pub webhook: Option<WebhookAlertConfig>,
    pub desktop_notifications: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAlertConfig {
    pub smtp_server: String,
    pub smtp_port: u16,
    pub username: String,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub use_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookAlertConfig {
    pub url: String,
    pub method: String,
    pub headers: std::collections::HashMap<String, String>,
    pub retry_count: u32,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub database_path: PathBuf,
    pub max_history_days: u32,
    pub cleanup_interval_hours: u32,
    pub compression_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file_enabled: bool,
    pub file_path: Option<PathBuf>,
    pub max_file_size_mb: u64,
    pub max_files: u32,
    pub console_enabled: bool,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiConfig {
    pub theme: String,
    pub refresh_interval_ms: u64,
    pub show_graphs: bool,
    pub graph_history_points: usize,
    pub decimal_places: u32,
    pub temperature_unit: String,
}


impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            cpu: MonitorSettings {
                enabled: true,
                interval_ms: 500,
                retain_history_seconds: 3600,
                warning_threshold: Some(80.0),
                critical_threshold: Some(95.0),
            },
            memory: MonitorSettings {
                enabled: true,
                interval_ms: 1000,
                retain_history_seconds: 3600,
                warning_threshold: Some(85.0),
                critical_threshold: Some(95.0),
            },
            gpu: MonitorSettings {
                enabled: true,
                interval_ms: 1000,
                retain_history_seconds: 3600,
                warning_threshold: Some(85.0),
                critical_threshold: Some(95.0),
            },
            disk: MonitorSettings {
                enabled: true,
                interval_ms: 2000,
                retain_history_seconds: 3600,
                warning_threshold: Some(85.0),
                critical_threshold: Some(95.0),
            },
            network: MonitorSettings {
                enabled: true,
                interval_ms: 1000,
                retain_history_seconds: 3600,
                warning_threshold: None,
                critical_threshold: None,
            },
            process: ProcessMonitorSettings {
                enabled: true,
                interval_ms: 2000,
                top_processes_count: 10,
                min_cpu_percent: 0.1,
                min_memory_mb: 10,
            },
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            email: None,
            webhook: None,
            desktop_notifications: true,
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        let data_dir = ProjectDirs::from("com", "system-monitor", "SystemMonitor")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("./data"));
        
        Self {
            database_path: data_dir.join("metrics.db"),
            max_history_days: 7,
            cleanup_interval_hours: 24,
            compression_enabled: true,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        let log_dir = ProjectDirs::from("com", "system-monitor", "SystemMonitor")
            .map(|dirs| dirs.data_dir().join("logs"))
            .unwrap_or_else(|| PathBuf::from("./logs"));
        
        Self {
            level: "info".to_string(),
            file_enabled: true,
            file_path: Some(log_dir.join("system-monitor.log")),
            max_file_size_mb: 10,
            max_files: 5,
            console_enabled: true,
            format: "default".to_string(),
        }
    }
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            refresh_interval_ms: 500,
            show_graphs: true,
            graph_history_points: 60,
            decimal_places: 1,
            temperature_unit: "celsius".to_string(),
        }
    }
}

pub struct ConfigManager {
    pub config_path: PathBuf,
    pub config: AppConfig,
}

impl ConfigManager {
    pub fn new() -> Result<Self, ConfigError> {
        let config_path = Self::default_config_path();
        let config = Self::load_or_create(&config_path)?;
        
        Ok(Self {
            config_path,
            config,
        })
    }
    
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let config_path = path.as_ref().to_path_buf();
        let config = Self::load_or_create(&config_path)?;
        
        Ok(Self {
            config_path,
            config,
        })
    }
    
    pub fn config(&self) -> &AppConfig {
        &self.config
    }
    
    pub fn config_mut(&mut self) -> &mut AppConfig {
        &mut self.config
    }
    
    pub fn save(&self) -> Result<(), ConfigError> {
        let config_str = toml::to_string_pretty(&self.config)
            .map_err(|e| ConfigError::Message(format!("Failed to serialize config: {}", e)))?;
        
        // Ensure parent directory exists
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| ConfigError::Message(format!("Failed to create config directory: {}", e)))?;
        }
        
        fs::write(&self.config_path, config_str)
            .map_err(|e| ConfigError::Message(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    pub fn reload(&mut self) -> Result<(), ConfigError> {
        self.config = Self::load_or_create(&self.config_path)?;
        Ok(())
    }
    
    fn default_config_path() -> PathBuf {
        ProjectDirs::from("com", "system-monitor", "SystemMonitor")
            .map(|dirs| dirs.config_dir().join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("./config.toml"))
    }
    
    fn load_or_create(path: &Path) -> Result<AppConfig, ConfigError> {
        if path.exists() {
            let settings = Config::builder()
                .add_source(File::from(path).format(FileFormat::Toml))
                .build()?;
            
            settings.try_deserialize()
        } else {
            // Create default config
            let config = AppConfig::default();
            
            // Save it for future use
            let config_str = toml::to_string_pretty(&config)
                .map_err(|e| ConfigError::Message(format!("Failed to serialize default config: {}", e)))?;
            
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| ConfigError::Message(format!("Failed to create config directory: {}", e)))?;
            }
            
            fs::write(path, config_str)
                .map_err(|e| ConfigError::Message(format!("Failed to write default config: {}", e)))?;
            
            Ok(config)
        }
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        let config = &self.config;
        
        // Validate monitoring intervals
        for (name, interval) in [
            ("CPU", config.monitoring.cpu.interval_ms),
            ("Memory", config.monitoring.memory.interval_ms),
            ("GPU", config.monitoring.gpu.interval_ms),
            ("Disk", config.monitoring.disk.interval_ms),
            ("Network", config.monitoring.network.interval_ms),
            ("Process", config.monitoring.process.interval_ms),
        ] {
            if interval < 100 {
                return Err(format!("{} monitoring interval must be at least 100ms", name));
            }
        }
        
        // Validate thresholds
        for (name, settings) in [
            ("CPU", &config.monitoring.cpu),
            ("Memory", &config.monitoring.memory),
            ("GPU", &config.monitoring.gpu),
            ("Disk", &config.monitoring.disk),
        ] {
            if let (Some(warn), Some(crit)) = (settings.warning_threshold, settings.critical_threshold) {
                if warn >= crit {
                    return Err(format!("{} warning threshold must be less than critical threshold", name));
                }
                if !(0.0..=100.0).contains(&warn) || !(0.0..=100.0).contains(&crit) {
                    return Err(format!("{} thresholds must be between 0 and 100", name));
                }
            }
        }
        
        // Validate storage settings
        if config.storage.max_history_days == 0 {
            return Err("Max history days must be greater than 0".to_string());
        }
        
        // Validate logging settings
        if !["trace", "debug", "info", "warn", "error"].contains(&config.logging.level.as_str()) {
            return Err("Invalid logging level".to_string());
        }
        
        // Validate UI settings
        if config.ui.graph_history_points == 0 {
            return Err("Graph history points must be greater than 0".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert!(config.monitoring.cpu.enabled);
        assert_eq!(config.monitoring.cpu.interval_ms, 500);
        assert_eq!(config.ui.theme, "dark");
    }
    
    #[test]
    fn test_config_save_load() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.toml");
        
        // Create and save config
        let mut manager = ConfigManager::from_path(&config_path).unwrap();
        manager.config_mut().ui.theme = "light".to_string();
        manager.save().unwrap();
        
        // Load config
        let loaded_manager = ConfigManager::from_path(&config_path).unwrap();
        assert_eq!(loaded_manager.config().ui.theme, "light");
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = AppConfig::default();
        config.monitoring.cpu.warning_threshold = Some(90.0);
        config.monitoring.cpu.critical_threshold = Some(80.0);
        
        let manager = ConfigManager {
            config_path: PathBuf::from("test.toml"),
            config,
        };
        
        assert!(manager.validate().is_err());
    }
}