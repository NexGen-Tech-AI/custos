use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::core::{Metric, MonitorError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub enabled: bool,
    pub interval_ms: u64,
    pub retain_history_seconds: u64,
    pub alert_thresholds: std::collections::HashMap<String, f64>,
    pub max_processes: Option<usize>,
    pub top_processes_count: Option<usize>,
    pub include_loopback: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_ms: 1000,
            retain_history_seconds: 3600,
            alert_thresholds: std::collections::HashMap::new(),
            max_processes: Some(100),
            top_processes_count: Some(10),
            include_loopback: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MonitorState {
    Uninitialized,
    Initializing,
    Running,
    Paused,
    Stopped,
    Error,
}

/// Core trait for implementing system monitors
/// 
/// This trait defines the interface that all monitoring implementations must follow.
/// It provides lifecycle management, metric collection, and feature discovery.
/// 
/// # Example Implementation
/// 
/// ```rust,ignore
/// use async_trait::async_trait;
/// use system_monitor::core::{Monitor, MonitorConfig, MonitorState, Metric, Result};
/// 
/// pub struct CustomMonitor {
///     state: MonitorState,
///     // ... other fields
/// }
/// 
/// #[async_trait]
/// impl Monitor for CustomMonitor {
///     fn name(&self) -> &str {
///         "Custom Monitor"
///     }
///     
///     fn state(&self) -> MonitorState {
///         self.state
///     }
///     
///     async fn initialize(&mut self, config: MonitorConfig) -> Result<()> {
///         // Initialize the monitor with configuration
///         self.state = MonitorState::Running;
///         Ok(())
///     }
///     
///     async fn collect(&mut self) -> Result<Vec<Metric>> {
///         // Collect and return metrics
///         Ok(vec![])
///     }
///     
///     // ... implement other required methods
/// }
/// ```
#[async_trait]
pub trait Monitor: Send + Sync {
    /// Returns the human-readable name of this monitor
    fn name(&self) -> &str;
    
    /// Returns the current state of the monitor
    fn state(&self) -> MonitorState;
    
    /// Initializes the monitor with the provided configuration
    /// 
    /// This method should prepare the monitor for operation but not start
    /// collecting metrics yet. Call `start()` to begin metric collection.
    async fn initialize(&mut self, config: MonitorConfig) -> Result<()>;
    
    /// Starts the monitor and begins metric collection
    async fn start(&mut self) -> Result<()>;
    
    /// Stops the monitor and ceases all metric collection
    async fn stop(&mut self) -> Result<()>;
    
    /// Temporarily pauses metric collection without stopping the monitor
    async fn pause(&mut self) -> Result<()>;
    
    /// Resumes metric collection after a pause
    async fn resume(&mut self) -> Result<()>;
    
    /// Collects and returns the current metrics
    /// 
    /// This is the main method that performs the actual monitoring work.
    /// It should be called periodically based on the configured interval.
    async fn collect(&mut self) -> Result<Vec<Metric>>;
    
    /// Returns the most recently collected metrics without performing new collection
    async fn get_current_metrics(&self) -> Result<Vec<Metric>>;
    
    /// Returns historical metrics for the specified duration
    /// 
    /// # Arguments
    /// 
    /// * `duration_seconds` - How far back in time to retrieve metrics
    async fn get_historical_metrics(&self, duration_seconds: u64) -> Result<Vec<Metric>>;
    
    /// Checks if this monitor supports a specific feature
    /// 
    /// # Arguments
    /// 
    /// * `feature` - The feature name to check (e.g., "cpu_temperature", "gpu_memory")
    fn supports_feature(&self, feature: &str) -> bool;
}

pub type SharedMonitor = Arc<RwLock<Box<dyn Monitor>>>;

#[derive(Clone)]
pub struct MonitorManager {
    monitors: Arc<RwLock<std::collections::HashMap<String, SharedMonitor>>>,
}

impl Default for MonitorManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MonitorManager {
    pub fn new() -> Self {
        Self {
            monitors: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn register_monitor(&self, name: String, monitor: Box<dyn Monitor>) -> Result<()> {
        let mut monitors = self.monitors.write().await;
        
        if monitors.contains_key(&name) {
            return Err(MonitorError::InvalidConfig(format!(
                "Monitor '{}' already registered",
                name
            )));
        }
        
        monitors.insert(name, Arc::new(RwLock::new(monitor)));
        Ok(())
    }

    pub async fn unregister_monitor(&self, name: &str) -> Result<()> {
        let mut monitors = self.monitors.write().await;
        
        if let Some(monitor) = monitors.remove(name) {
            let mut m = monitor.write().await;
            m.stop().await?;
        }
        
        Ok(())
    }

    pub async fn get_monitor(&self, name: &str) -> Option<SharedMonitor> {
        let monitors = self.monitors.read().await;
        monitors.get(name).cloned()
    }

    pub async fn start_all(&self) -> Result<()> {
        let monitors = self.monitors.read().await;
        
        for (_, monitor) in monitors.iter() {
            let mut m = monitor.write().await;
            m.start().await?;
        }
        
        Ok(())
    }

    pub async fn stop_all(&self) -> Result<()> {
        let monitors = self.monitors.read().await;
        
        for (_, monitor) in monitors.iter() {
            let mut m = monitor.write().await;
            m.stop().await?;
        }
        
        Ok(())
    }

    pub async fn collect_all_metrics(&self) -> Result<std::collections::HashMap<String, Vec<Metric>>> {
        let monitors = self.monitors.read().await;
        let mut all_metrics = std::collections::HashMap::new();
        
        for (name, monitor) in monitors.iter() {
            let mut m = monitor.write().await;
            match m.collect().await {
                Ok(metrics) => {
                    all_metrics.insert(name.clone(), metrics);
                }
                Err(e) => {
                    tracing::error!("Failed to collect metrics from {}: {}", name, e);
                }
            }
        }
        
        Ok(all_metrics)
    }
}