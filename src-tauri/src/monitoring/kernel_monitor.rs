use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use crossbeam::channel::{bounded, Sender, Receiver};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use tracing::{info, warn, error};

#[cfg(target_os = "linux")]
use crate::monitoring::linux_ebpf::LinuxHardwareCounters;

#[cfg(target_os = "windows")]
use crate::monitoring::windows_etw::WindowsEtwMonitor;

#[derive(Error, Debug)]
pub enum KernelMonitorError {
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    #[error("System call failed: {0}")]
    SystemCallFailed(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelMetrics {
    pub timestamp: u64,  // Nanosecond precision
    pub cpu: KernelCpuMetrics,
    pub memory: KernelMemoryMetrics,
    pub disk: KernelDiskMetrics,
    pub network: KernelNetworkMetrics,
    pub latency: KernelLatencyMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelCpuMetrics {
    pub cycles: u64,
    pub instructions: u64,
    pub cache_misses: u64,
    pub branch_misses: u64,
    pub cpu_usage_percent: f64,
    pub frequency_mhz: u64,
    pub temperature_celsius: Option<f64>,
    pub power_watts: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelMemoryMetrics {
    pub page_faults: u64,
    pub page_ins: u64,
    pub page_outs: u64,
    pub swap_ins: u64,
    pub swap_outs: u64,
    pub memory_pressure: f64,
    pub numa_hits: u64,
    pub numa_misses: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelDiskMetrics {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub io_wait_time: u64,
    pub queue_depth: u32,
    pub latency_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelNetworkMetrics {
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors_in: u64,
    pub errors_out: u64,
    pub drops_in: u64,
    pub drops_out: u64,
    pub latency_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelLatencyMetrics {
    pub collection_latency_ns: u64,
    pub processing_latency_ns: u64,
    pub total_latency_ns: u64,
}

pub struct KernelMonitor {
    sender: Sender<KernelMetrics>,
    receiver: Receiver<KernelMetrics>,
    running: Arc<Mutex<bool>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl KernelMonitor {
    pub fn new() -> Result<Self, KernelMonitorError> {
        let (sender, receiver) = bounded(1000); // High-capacity channel
        
        Ok(Self {
            sender,
            receiver,
            running: Arc::new(Mutex::new(false)),
            thread_handle: None,
        })
    }

    pub fn start(&mut self) -> Result<(), KernelMonitorError> {
        if *self.running.lock() {
            return Ok(());
        }

        *self.running.lock() = true;
        let sender = self.sender.clone();
        let running = self.running.clone();

        let handle = std::thread::spawn(move || {
            Self::monitoring_loop(sender, running);
        });

        self.thread_handle = Some(handle);
        info!("Kernel-level monitoring started");
        Ok(())
    }

    pub fn stop(&mut self) {
        *self.running.lock() = false;
        
        if let Some(handle) = self.thread_handle.take() {
            if let Err(e) = handle.join() {
                error!("Failed to join kernel monitoring thread: {:?}", e);
            }
        }
        
        info!("Kernel-level monitoring stopped");
    }

    pub fn get_latest_metrics(&self) -> Option<KernelMetrics> {
        self.receiver.try_recv().ok()
    }

    fn monitoring_loop(sender: Sender<KernelMetrics>, running: Arc<Mutex<bool>>) {
        while *running.lock() {
            let start = Instant::now();
            
            // Collect kernel-level metrics with nanosecond precision
            match Self::collect_kernel_metrics() {
                Ok(mut metrics) => {
                    let collection_latency = start.elapsed().as_nanos() as u64;
                    let processing_start = Instant::now();
                    
                    // Calculate latencies
                    metrics.latency.collection_latency_ns = collection_latency;
                    metrics.latency.processing_latency_ns = processing_start.elapsed().as_nanos() as u64;
                    metrics.latency.total_latency_ns = start.elapsed().as_nanos() as u64;
                    
                    // Send metrics (non-blocking)
                    if let Err(e) = sender.try_send(metrics) {
                        warn!("Failed to send kernel metrics: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to collect kernel metrics: {}", e);
                }
            }
            
                         // Sleep for 3 seconds between collections
            let elapsed = start.elapsed();
                         if elapsed < Duration::from_secs(3) {
                 std::thread::sleep(Duration::from_secs(3) - elapsed);
            }
        }
    }

    fn collect_kernel_metrics() -> Result<KernelMetrics, KernelMonitorError> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                Self::collect_linux_kernel_metrics()
            } else if #[cfg(target_os = "windows")] {
                Self::collect_windows_kernel_metrics()
            } else {
                Err(KernelMonitorError::UnsupportedPlatform(
                    std::env::consts::OS.to_string()
                ))
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn collect_linux_kernel_metrics() -> Result<KernelMetrics, KernelMonitorError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_nanos() as u64;

        // Collect hardware performance counters via perf_event
        let hw_counters = match LinuxHardwareCounters::new() {
            Ok(mut counters) => {
                // Start the counters
                let _ = counters.start();

                // Give it a moment to collect data
                std::thread::sleep(Duration::from_millis(10));

                // Read the values
                match counters.read_values() {
                    Ok(values) => Some(values),
                    Err(e) => {
                        warn!("Failed to read hardware counters: {}", e);
                        None
                    }
                }
            },
            Err(e) => {
                warn!("Failed to create hardware counters (may need CAP_PERFMON): {}", e);
                None
            }
        };

        // Extract hardware counter values or use defaults
        let (cycles, instructions, cache_misses, branch_misses, page_faults_hw, _context_switches) =
            if let Some(counters) = hw_counters {
                (counters.cpu_cycles, counters.instructions, counters.cache_misses,
                 counters.branch_misses, counters.page_faults, counters.context_switches)
            } else {
                (0, 0, 0, 0, 0, 0)
            };

        // Read CPU frequency from /proc/cpuinfo
        let frequency_mhz = Self::read_cpu_frequency();

        // Read CPU temperature from /sys/class/thermal
        let temperature_celsius = Self::read_cpu_temperature();

        // Read memory metrics from /proc/vmstat
        let (page_ins, page_outs, swap_ins, swap_outs) = Self::read_vmstat();

        // Read disk I/O metrics from /proc/diskstats
        let (disk_read_bytes, disk_write_bytes, disk_read_ops, disk_write_ops) = Self::read_diskstats();

        // Read network metrics from /proc/net/dev
        let (net_bytes_in, net_bytes_out, net_packets_in, net_packets_out, net_errors_in, net_errors_out) =
            Self::read_net_dev();

        // Calculate CPU usage percentage (simplified)
        let cpu_usage_percent = if instructions > 0 {
            ((cycles as f64 / instructions as f64) * 100.0).min(100.0)
        } else {
            0.0
        };

        Ok(KernelMetrics {
            timestamp,
            cpu: KernelCpuMetrics {
                cycles,
                instructions,
                cache_misses,
                branch_misses,
                cpu_usage_percent,
                frequency_mhz,
                temperature_celsius,
                power_watts: None, // TODO: Read from /sys/class/powercap
            },
            memory: KernelMemoryMetrics {
                page_faults: page_faults_hw,
                page_ins,
                page_outs,
                swap_ins,
                swap_outs,
                memory_pressure: 0.0, // TODO: Calculate from PSI
                numa_hits: 0,         // TODO: Read from /sys/devices/system/node
                numa_misses: 0,       // TODO: Read from /sys/devices/system/node
            },
            disk: KernelDiskMetrics {
                read_bytes: disk_read_bytes,
                write_bytes: disk_write_bytes,
                read_ops: disk_read_ops,
                write_ops: disk_write_ops,
                io_wait_time: 0,      // TODO: Read from /proc/stat
                queue_depth: 0,       // TODO: Read from /sys/block/*/queue/nr_requests
                latency_ns: 0,        // TODO: Calculate from timestamps
            },
            network: KernelNetworkMetrics {
                packets_in: net_packets_in,
                packets_out: net_packets_out,
                bytes_in: net_bytes_in,
                bytes_out: net_bytes_out,
                errors_in: net_errors_in,
                errors_out: net_errors_out,
                drops_in: 0,          // TODO: Parse from /proc/net/dev
                drops_out: 0,         // TODO: Parse from /proc/net/dev
                latency_ns: 0,        // TODO: Measure via RTT
            },
            latency: KernelLatencyMetrics {
                collection_latency_ns: 0,
                processing_latency_ns: 0,
                total_latency_ns: 0,
            },
        })
    }

    // Helper function to read CPU frequency from /proc/cpuinfo
    #[cfg(target_os = "linux")]
    fn read_cpu_frequency() -> u64 {
        if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in content.lines() {
                if line.starts_with("cpu MHz") {
                    if let Some(freq_str) = line.split(':').nth(1) {
                        if let Ok(freq) = freq_str.trim().parse::<f64>() {
                            return freq as u64;
                        }
                    }
                }
            }
        }
        0
    }

    // Helper function to read CPU temperature from thermal zones
    #[cfg(target_os = "linux")]
    fn read_cpu_temperature() -> Option<f64> {
        // Try to read from thermal zone 0 (usually CPU)
        if let Ok(temp_str) = std::fs::read_to_string("/sys/class/thermal/thermal_zone0/temp") {
            if let Ok(temp_millidegrees) = temp_str.trim().parse::<i64>() {
                return Some(temp_millidegrees as f64 / 1000.0);
            }
        }
        None
    }

    // Helper function to read memory stats from /proc/vmstat
    #[cfg(target_os = "linux")]
    fn read_vmstat() -> (u64, u64, u64, u64) {
        let mut page_ins = 0u64;
        let mut page_outs = 0u64;
        let mut swap_ins = 0u64;
        let mut swap_outs = 0u64;

        if let Ok(content) = std::fs::read_to_string("/proc/vmstat") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    match parts[0] {
                        "pgpgin" => page_ins = parts[1].parse().unwrap_or(0),
                        "pgpgout" => page_outs = parts[1].parse().unwrap_or(0),
                        "pswpin" => swap_ins = parts[1].parse().unwrap_or(0),
                        "pswpout" => swap_outs = parts[1].parse().unwrap_or(0),
                        _ => {}
                    }
                }
            }
        }

        (page_ins, page_outs, swap_ins, swap_outs)
    }

    // Helper function to read disk stats from /proc/diskstats
    #[cfg(target_os = "linux")]
    fn read_diskstats() -> (u64, u64, u64, u64) {
        let mut read_bytes = 0u64;
        let mut write_bytes = 0u64;
        let mut read_ops = 0u64;
        let mut write_ops = 0u64;

        if let Ok(content) = std::fs::read_to_string("/proc/diskstats") {
            for line in content.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Format: major minor name reads ... sectors_read ... writes ... sectors_written
                if parts.len() >= 14 {
                    // Skip loop and ram devices
                    if !parts[2].starts_with("loop") && !parts[2].starts_with("ram") {
                        read_ops += parts[3].parse::<u64>().unwrap_or(0);
                        read_bytes += parts[5].parse::<u64>().unwrap_or(0) * 512; // sectors to bytes
                        write_ops += parts[7].parse::<u64>().unwrap_or(0);
                        write_bytes += parts[9].parse::<u64>().unwrap_or(0) * 512;
                    }
                }
            }
        }

        (read_bytes, write_bytes, read_ops, write_ops)
    }

    // Helper function to read network stats from /proc/net/dev
    #[cfg(target_os = "linux")]
    fn read_net_dev() -> (u64, u64, u64, u64, u64, u64) {
        let mut bytes_in = 0u64;
        let mut bytes_out = 0u64;
        let mut packets_in = 0u64;
        let mut packets_out = 0u64;
        let mut errors_in = 0u64;
        let mut errors_out = 0u64;

        if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
            for line in content.lines().skip(2) { // Skip header lines
                if let Some(colon_pos) = line.find(':') {
                    let interface = line[..colon_pos].trim();

                    // Skip loopback
                    if interface == "lo" {
                        continue;
                    }

                    let stats = &line[colon_pos + 1..];
                    let parts: Vec<&str> = stats.split_whitespace().collect();

                    if parts.len() >= 16 {
                        bytes_in += parts[0].parse::<u64>().unwrap_or(0);
                        packets_in += parts[1].parse::<u64>().unwrap_or(0);
                        errors_in += parts[2].parse::<u64>().unwrap_or(0);
                        bytes_out += parts[8].parse::<u64>().unwrap_or(0);
                        packets_out += parts[9].parse::<u64>().unwrap_or(0);
                        errors_out += parts[10].parse::<u64>().unwrap_or(0);
                    }
                }
            }
        }

        (bytes_in, bytes_out, packets_in, packets_out, errors_in, errors_out)
    }

    #[cfg(target_os = "windows")]
    fn collect_windows_kernel_metrics() -> Result<KernelMetrics, KernelMonitorError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_nanos() as u64;

        // Collect Windows Performance Counters
        let monitor = WindowsEtwMonitor::new()
            .map_err(|e| KernelMonitorError::SystemCallFailed(e.to_string()))?;

        let metrics = monitor.collect_metrics()
            .map_err(|e| KernelMonitorError::SystemCallFailed(e.to_string()))?;

        // Read additional system information
        let (frequency_mhz, temperature_celsius) = Self::read_windows_cpu_info();
        let (page_ins, page_outs) = Self::read_windows_page_metrics();
        let (disk_read_ops, disk_write_ops) = Self::read_windows_disk_ops();

        Ok(KernelMetrics {
            timestamp,
            cpu: KernelCpuMetrics {
                cycles: 0, // TODO: Requires PMU access via driver
                instructions: 0,
                cache_misses: 0,
                branch_misses: 0,
                cpu_usage_percent: metrics.cpu_usage,
                frequency_mhz,
                temperature_celsius,
                power_watts: None, // TODO: Read from WMI Win32_Processor
            },
            memory: KernelMemoryMetrics {
                page_faults: metrics.page_faults,
                page_ins,
                page_outs,
                swap_ins: 0, // TODO: Read from Performance Counters
                swap_outs: 0,
                memory_pressure: 0.0, // TODO: Calculate from available memory
                numa_hits: 0,
                numa_misses: 0,
            },
            disk: KernelDiskMetrics {
                read_bytes: metrics.disk_io / 2, // Rough approximation
                write_bytes: metrics.disk_io / 2,
                read_ops: disk_read_ops,
                write_ops: disk_write_ops,
                io_wait_time: 0,
                queue_depth: 0,
                latency_ns: 0,
            },
            network: KernelNetworkMetrics {
                packets_in: 0,
                packets_out: 0,
                bytes_in: metrics.network_io / 2,
                bytes_out: metrics.network_io / 2,
                errors_in: 0,
                errors_out: 0,
                drops_in: 0,
                drops_out: 0,
                latency_ns: 0,
            },
            latency: KernelLatencyMetrics {
                collection_latency_ns: 0,
                processing_latency_ns: 0,
                total_latency_ns: 0,
            },
        })
    }

    #[cfg(target_os = "windows")]
    fn read_windows_cpu_info() -> (u64, Option<f64>) {
        use std::process::Command;

        // Read CPU frequency
        let frequency = if let Ok(output) = Command::new("wmic")
            .args(&["cpu", "get", "CurrentClockSpeed", "/value"])
            .output()
        {
            let output_str = String::from_utf8_lossy(&output.stdout);
            output_str
                .lines()
                .find(|line| line.starts_with("CurrentClockSpeed="))
                .and_then(|line| line.split('=').nth(1))
                .and_then(|val| val.trim().parse::<u64>().ok())
                .unwrap_or(0)
        } else {
            0
        };

        // Read CPU temperature (may not be available without WMI extensions)
        let temperature = None; // Windows doesn't expose CPU temp easily

        (frequency, temperature)
    }

    #[cfg(target_os = "windows")]
    fn read_windows_page_metrics() -> (u64, u64) {
        use std::process::Command;

        let page_ins = if let Ok(output) = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                r"Get-Counter '\Memory\Pages Input/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"
            ])
            .output()
        {
            let value_str = String::from_utf8_lossy(&output.stdout);
            value_str.trim().parse::<f64>().unwrap_or(0.0) as u64
        } else {
            0
        };

        let page_outs = if let Ok(output) = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                r"Get-Counter '\Memory\Pages Output/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"
            ])
            .output()
        {
            let value_str = String::from_utf8_lossy(&output.stdout);
            value_str.trim().parse::<f64>().unwrap_or(0.0) as u64
        } else {
            0
        };

        (page_ins, page_outs)
    }

    #[cfg(target_os = "windows")]
    fn read_windows_disk_ops() -> (u64, u64) {
        use std::process::Command;

        let read_ops = if let Ok(output) = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                r"Get-Counter '\PhysicalDisk(_Total)\Disk Reads/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"
            ])
            .output()
        {
            let value_str = String::from_utf8_lossy(&output.stdout);
            value_str.trim().parse::<f64>().unwrap_or(0.0) as u64
        } else {
            0
        };

        let write_ops = if let Ok(output) = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-Command",
                r"Get-Counter '\PhysicalDisk(_Total)\Disk Writes/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object -ExpandProperty CookedValue"
            ])
            .output()
        {
            let value_str = String::from_utf8_lossy(&output.stdout);
            value_str.trim().parse::<f64>().unwrap_or(0.0) as u64
        } else {
            0
        };

        (read_ops, write_ops)
    }
}

impl Drop for KernelMonitor {
    fn drop(&mut self) {
        self.stop();
    }
} 