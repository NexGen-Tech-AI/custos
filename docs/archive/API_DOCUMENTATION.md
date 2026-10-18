# System Monitor API Documentation

## Overview

The System Monitor library provides a comprehensive, modular API for monitoring system resources in real-time. It's designed with performance, safety, and extensibility in mind.

## Architecture

```
┌─────────────────────┐
│  MonitoringService  │  High-level service orchestration
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│   MonitorManager    │  Manages monitor lifecycle
└──────────┬──────────┘
           │
┌──────────▼──────────┐
│   Monitor Trait     │  Core abstraction
└──────────┬──────────┘
           │
     ┌─────┴─────┬─────────┬───────────┬────────────┬──────────┐
     │           │         │           │            │          │
┌────▼───┐ ┌────▼───┐ ┌───▼───┐ ┌────▼────┐ ┌─────▼────┐ ┌───▼────┐
│  CPU   │ │ Memory │ │  GPU  │ │ Storage │ │ Network  │ │Process │
└────────┘ └────────┘ └───────┘ └─────────┘ └──────────┘ └────────┘
```

## Core Components

### 1. Monitor Trait

The foundation of the monitoring system. All monitors implement this trait.

```rust
#[async_trait]
pub trait Monitor: Send + Sync {
    fn name(&self) -> &str;
    fn state(&self) -> MonitorState;
    async fn initialize(&mut self, config: MonitorConfig) -> Result<()>;
    async fn start(&mut self) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
    async fn collect(&mut self) -> Result<Vec<Metric>>;
    // ... more methods
}
```

### 2. Metric Types

```rust
pub enum MetricType {
    // CPU Metrics
    CpuUsage,
    CpuFrequency,
    CpuTemperature,
    ProcessCount,
    
    // Memory Metrics
    MemoryUsage,
    MemoryAvailable,
    SwapUsage,
    
    // GPU Metrics
    GpuUsage,
    GpuTemperature,
    GpuMemoryUsage,
    GpuPower,
    GpuFanSpeed,
    
    // Storage Metrics
    DiskUsage,
    DiskSpace,
    DiskIo,
    
    // Network Metrics
    NetworkThroughput,
    NetworkBytes,
    NetworkStatus,
    NetworkSpeed,
    
    // Process Metrics
    ProcessCpu,
    ProcessMemory,
    ProcessDiskIo,
}
```

### 3. Configuration System

Comprehensive configuration via TOML files:

```toml
[monitoring.cpu]
enabled = true
interval_ms = 500
warning_threshold = 80.0
critical_threshold = 95.0

[alerts]
enabled = true
desktop_notifications = true

[storage]
database_path = "./data/metrics.db"
max_history_days = 7
```

## Usage Examples

### Basic Usage

```rust
use system_monitor::services::MonitoringService;
use system_monitor::core::ConfigManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize service
    let service = MonitoringService::new();
    service.initialize().await?;
    service.start().await?;
    
    // Subscribe to metrics
    let mut receiver = service.subscribe();
    
    while let Ok(metrics) = receiver.recv().await {
        println!("CPU: {:.1}%", metrics.cpu.usage_percent);
        println!("Memory: {:.1}%", metrics.memory.usage_percent);
    }
    
    Ok(())
}
```

### Custom Monitor Implementation

```rust
use async_trait::async_trait;
use system_monitor::core::{Monitor, MonitorConfig, MonitorState, Metric, Result};

pub struct CustomMonitor {
    state: MonitorState,
}

#[async_trait]
impl Monitor for CustomMonitor {
    fn name(&self) -> &str {
        "Custom Monitor"
    }
    
    async fn collect(&mut self) -> Result<Vec<Metric>> {
        // Implement custom metric collection
        Ok(vec![])
    }
    
    // ... implement other required methods
}
```

### Configuration Management

```rust
use system_monitor::core::{ConfigManager, AppConfig};

// Load configuration
let mut config_manager = ConfigManager::new()?;

// Modify settings
config_manager.config_mut().monitoring.cpu.interval_ms = 250;

// Save changes
config_manager.save()?;

// Apply to service
monitoring_service.apply_config(config_manager.config()).await?;
```

## Available Monitors

### CPU Monitor
- Overall and per-core usage
- Frequency monitoring
- Temperature (platform-dependent)
- Load average
- Process counts
- Context switches (Linux)

### Memory Monitor
- RAM usage and availability
- Swap usage
- Cache statistics

### GPU Monitor
- Supports NVIDIA (via NVML), AMD, and Intel GPUs
- Usage percentage
- Temperature
- Memory usage
- Power consumption
- Fan speed

### Storage Monitor
- Disk usage by mount point
- I/O statistics
- Read/write rates

### Network Monitor
- Interface statistics
- Throughput calculation
- Connection status
- Error counts

### Process Monitor
- Top processes by CPU/memory
- Process lifecycle tracking
- Resource usage per process

## Error Handling

All operations return `Result<T, MonitorError>`:

```rust
pub enum MonitorError {
    NotInitialized,
    AlreadyRunning,
    NotRunning,
    InvalidConfig(String),
    CollectionError(String),
    SystemError(String),
}
```

## Performance Considerations

1. **Async Design**: All operations are async, preventing blocking
2. **Configurable Intervals**: Adjust collection frequency per monitor
3. **History Management**: Automatic cleanup of old metrics
4. **Efficient Storage**: In-memory circular buffers with configurable retention

## Platform Support

| Feature | Linux | Windows | macOS |
|---------|-------|---------|-------|
| CPU Monitoring | ✓ | ✓ | ✓ |
| Memory Monitoring | ✓ | ✓ | ✓ |
| GPU (NVIDIA) | ✓ | ✓ | ✓ |
| GPU (AMD) | ✓ | ◐ | ✗ |
| GPU (Intel) | ✓ | ◐ | ✗ |
| Disk I/O | ✓ | ✓ | ✓ |
| Network | ✓ | ✓ | ✓ |
| Temperature | ✓ | ◐ | ◐ |

✓ Full support | ◐ Partial support | ✗ Not supported

## Thread Safety

All monitors are thread-safe through:
- `Arc<RwLock<T>>` for shared state
- `Send + Sync` trait bounds
- Immutable configuration after initialization

## Best Practices

1. **Initialize Once**: Create monitors at startup and reuse
2. **Configure Appropriately**: Balance accuracy vs performance with intervals
3. **Handle Errors**: Not all metrics available on all platforms
4. **Monitor Lifecycle**: Always stop monitors when done
5. **Use Subscriptions**: For real-time updates, use the broadcast channel

## Contributing

To add a new monitor:

1. Implement the `Monitor` trait
2. Add metric types to `MetricType` enum
3. Register with `MonitorManager`
4. Add configuration options
5. Document platform support

## API Stability

This library follows semantic versioning. The `Monitor` trait and core types are stable. Backend implementations may change between minor versions.