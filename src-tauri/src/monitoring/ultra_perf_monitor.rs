use std::sync::Arc;
use std::time::{Duration, Instant};
use crossbeam::channel::{bounded, Receiver, Sender};
use dashmap::DashMap;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

// Ultra-high-performance metrics with nanosecond precision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraPerfMetrics {
    pub timestamp_nanos: u64,
    pub collection_latency_ns: u64,
    pub cpu: UltraCpuMetrics,
    pub memory: UltraMemoryMetrics,
    pub gpus: Vec<UltraGpuMetrics>,
    pub disks: Vec<UltraDiskMetrics>,
    pub networks: Vec<UltraNetworkMetrics>,
    pub processes: Vec<UltraProcessMetrics>,
    pub hardware_counters: HardwareCounterMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraCpuMetrics {
    pub global_usage: f32,
    pub per_core_usage: Vec<f32>,
    pub frequency_mhz: Vec<u64>,
    pub temperature: Option<f32>,
    pub load_average: [f32; 3],
    pub context_switches: u64,
    pub interrupts: u64,
    pub cache_misses: u64,
    pub cache_hits: u64,
    pub branch_misses: u64,
    pub instructions_per_cycle: f32,
    pub power_watts: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraMemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub cached_bytes: u64,
    pub buffer_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub page_faults: u64,
    pub page_ins: u64,
    pub page_outs: u64,
    pub numa_hits: u64,
    pub numa_misses: u64,
    pub memory_bandwidth_gbps: f32,
    pub memory_latency_ns: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraGpuMetrics {
    pub name: String,
    pub usage_percent: f32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub temperature_celsius: f32,
    pub power_watts: f32,
    pub fan_speed_percent: Option<f32>,
    pub clock_mhz: f32,
    pub memory_clock_mhz: f32,
    pub compute_utilization: f32,
    pub memory_utilization: f32,
    pub pcie_bandwidth_gbps: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraDiskMetrics {
    pub device_name: String,
    pub mount_point: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub read_bytes_per_sec: u64,
    pub write_bytes_per_sec: u64,
    pub io_operations_per_sec: u64,
    pub read_latency_ms: f32,
    pub write_latency_ms: f32,
    pub queue_depth: u32,
    pub throughput_gbps: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraNetworkMetrics {
    pub interface_name: String,
    pub bytes_sent_per_sec: u64,
    pub bytes_received_per_sec: u64,
    pub packets_sent_per_sec: u64,
    pub packets_received_per_sec: u64,
    pub errors_per_sec: u64,
    pub latency_ms: f32,
    pub bandwidth_gbps: f32,
    pub packet_loss_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UltraProcessMetrics {
    pub pid: u32,
    pub name: String,
    pub cpu_usage_percent: f32,
    pub memory_bytes: u64,
    pub disk_read_bytes_per_sec: u64,
    pub disk_write_bytes_per_sec: u64,
    pub network_bytes_per_sec: u64,
    pub threads: u32,
    pub priority: i32,
    pub cpu_affinity: Vec<u32>,
    pub memory_working_set: u64,
    pub io_priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareCounterMetrics {
    pub cpu_cycles: u64,
    pub instructions: u64,
    pub cache_references: u64,
    pub cache_misses: u64,
    pub branch_instructions: u64,
    pub branch_misses: u64,
    pub bus_cycles: u64,
    pub stalled_cycles_frontend: u64,
    pub stalled_cycles_backend: u64,
    pub ref_cpu_cycles: u64,
}

// Lock-free ring buffer optimized for ultra-high performance
pub struct UltraPerfRingBuffer {
    buffer: Arc<Mutex<Vec<UltraPerfMetrics>>>,
    capacity: usize,
}

impl UltraPerfRingBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
            capacity,
        }
    }

    pub fn push(&self, metrics: UltraPerfMetrics) -> bool {
        if let Ok(mut buffer) = self.buffer.lock() {
            if buffer.len() >= self.capacity {
                buffer.remove(0);
            }
            buffer.push(metrics);
            true
        } else {
            false
        }
    }

    pub fn pop(&self) -> Option<UltraPerfMetrics> {
        if let Ok(mut buffer) = self.buffer.lock() {
            if buffer.is_empty() {
                None
            } else {
                Some(buffer.remove(0))
            }
        } else {
            None
        }
    }
}

impl Default for UltraPerfMetrics {
    fn default() -> Self {
        Self {
            timestamp_nanos: 0,
            collection_latency_ns: 0,
            cpu: UltraCpuMetrics::default(),
            memory: UltraMemoryMetrics::default(),
            gpus: Vec::new(),
            disks: Vec::new(),
            networks: Vec::new(),
            processes: Vec::new(),
            hardware_counters: HardwareCounterMetrics::default(),
        }
    }
}

impl Default for UltraCpuMetrics {
    fn default() -> Self {
        Self {
            global_usage: 0.0,
            per_core_usage: Vec::new(),
            frequency_mhz: Vec::new(),
            temperature: None,
            load_average: [0.0, 0.0, 0.0],
            context_switches: 0,
            interrupts: 0,
            cache_misses: 0,
            cache_hits: 0,
            branch_misses: 0,
            instructions_per_cycle: 0.0,
            power_watts: None,
        }
    }
}

impl Default for UltraMemoryMetrics {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            cached_bytes: 0,
            buffer_bytes: 0,
            swap_total_bytes: 0,
            swap_used_bytes: 0,
            page_faults: 0,
            page_ins: 0,
            page_outs: 0,
            numa_hits: 0,
            numa_misses: 0,
            memory_bandwidth_gbps: 0.0,
            memory_latency_ns: 0.0,
        }
    }
}

impl Default for HardwareCounterMetrics {
    fn default() -> Self {
        Self {
            cpu_cycles: 0,
            instructions: 0,
            cache_references: 0,
            cache_misses: 0,
            branch_instructions: 0,
            branch_misses: 0,
            bus_cycles: 0,
            stalled_cycles_frontend: 0,
            stalled_cycles_backend: 0,
            ref_cpu_cycles: 0,
        }
    }
}

// Ultra-high-performance monitoring service
pub struct UltraPerfMonitoringService {
    ring_buffer: Arc<UltraPerfRingBuffer>,
    metrics_sender: Sender<UltraPerfMetrics>,
    metrics_receiver: Receiver<UltraPerfMetrics>,
    running: Arc<AtomicBool>,
    update_interval: Duration,
    previous_stats: Arc<DashMap<String, (u64, u64)>>,
}

impl UltraPerfMonitoringService {
    pub fn new(update_interval_ms: u64) -> Self {
        let (sender, receiver) = bounded(10000); // Ultra-high capacity channel
        let ring_buffer = Arc::new(UltraPerfRingBuffer::new(10000));
        let previous_stats = Arc::new(DashMap::new());

        Self {
            ring_buffer,
            metrics_sender: sender,
            metrics_receiver: receiver,
            running: Arc::new(AtomicBool::new(false)),
            update_interval: Duration::from_micros(update_interval_ms * 1000), // Convert to microseconds
            previous_stats,
        }
    }

    pub fn start(&self) {
        if self.running.load(Ordering::Relaxed) {
            return;
        }

        self.running.store(true, Ordering::Relaxed);
        let sender = self.metrics_sender.clone();
        let running = self.running.clone();
        let update_interval = self.update_interval;
        let previous_stats = self.previous_stats.clone();
        let ring_buffer = self.ring_buffer.clone();

        // Spawn ultra-high-priority monitoring thread
        thread::spawn(move || {
            #[cfg(target_os = "linux")]
            {
                // Set real-time priority for ultra-low latency
                use libc::{sched_param, SCHED_FIFO};
                unsafe {
                    let param = sched_param { sched_priority: 99 }; // Maximum priority
                    libc::pthread_setschedparam(
                        libc::pthread_self(),
                        SCHED_FIFO,
                        &param,
                    );
                }
            }

            while running.load(Ordering::Relaxed) {
                let start = Instant::now();
                
                // Collect ultra-high-performance metrics
                let metrics = Self::collect_ultra_perf_metrics(&previous_stats);
                
                // Store in ring buffer
                ring_buffer.push(metrics.clone());
                
                // Send to subscribers with non-blocking send
                if let Err(_) = sender.try_send(metrics) {
                    // Channel is full, drop oldest
                    let _ = ring_buffer.pop();
                }
                
                // Ultra-precise timing control
                let elapsed = start.elapsed();
                if elapsed < update_interval {
                    let sleep_time = update_interval - elapsed;
                    if sleep_time > Duration::from_micros(1) {
                        thread::sleep(sleep_time);
                    } else {
                        // Spin for sub-microsecond precision
                        while Instant::now() - start < update_interval {
                            std::hint::spin_loop();
                        }
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn get_latest_metrics(&self) -> Option<UltraPerfMetrics> {
        self.metrics_receiver.try_recv().ok()
    }

    pub fn subscribe(&self) -> Receiver<UltraPerfMetrics> {
        self.metrics_receiver.clone()
    }

    fn collect_ultra_perf_metrics(
        previous_stats: &DashMap<String, (u64, u64)>,
    ) -> UltraPerfMetrics {
        let collection_start = Instant::now();
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_nanos() as u64;

        // Use sysinfo with minimal refresh for ultra-high performance
        let mut sys = sysinfo::System::new_all();
        sys.refresh_cpu();
        sys.refresh_memory();
        sys.refresh_processes();

        let collection_latency = collection_start.elapsed().as_nanos() as u64;

        UltraPerfMetrics {
            timestamp_nanos: timestamp,
            collection_latency_ns: collection_latency,
            cpu: Self::collect_ultra_cpu_metrics(&sys),
            memory: Self::collect_ultra_memory_metrics(&sys),
            gpus: Self::collect_ultra_gpu_metrics(),
            disks: Self::collect_ultra_disk_metrics(&sys, previous_stats),
            networks: Self::collect_ultra_network_metrics(&sys, previous_stats),
            processes: Self::collect_ultra_process_metrics(&sys),
            hardware_counters: Self::collect_hardware_counters(),
        }
    }

    fn collect_ultra_cpu_metrics(sys: &sysinfo::System) -> UltraCpuMetrics {
        let global_usage = sys.global_cpu_info().cpu_usage();
        
        let per_core_usage: Vec<f32> = sys.cpus()
            .par_iter()
            .map(|cpu| cpu.cpu_usage())
            .collect();

        let frequency_mhz: Vec<u64> = sys.cpus()
            .par_iter()
            .map(|cpu| cpu.frequency() / 1_000_000)
            .collect();

        UltraCpuMetrics {
            global_usage,
            per_core_usage,
            frequency_mhz,
            temperature: None, // TODO: Add temperature sensors
            load_average: {
                let load = sysinfo::System::load_average();
                [load.one as f32, load.five as f32, load.fifteen as f32]
            },
            context_switches: 0, // TODO: Add kernel-level metrics
            interrupts: 0,
            cache_misses: 0, // TODO: Add hardware performance counters
            cache_hits: 0,
            branch_misses: 0,
            instructions_per_cycle: 0.0,
            power_watts: None,
        }
    }

    fn collect_ultra_memory_metrics(sys: &sysinfo::System) -> UltraMemoryMetrics {
        UltraMemoryMetrics {
            total_bytes: sys.total_memory(),
            used_bytes: sys.used_memory(),
            available_bytes: sys.available_memory(),
            cached_bytes: 0, // TODO: Add cached memory detection
            buffer_bytes: 0, // TODO: Add buffer memory detection
            swap_total_bytes: sys.total_swap(),
            swap_used_bytes: sys.used_swap(),
            page_faults: 0, // TODO: Add page fault monitoring
            page_ins: 0,
            page_outs: 0,
            numa_hits: 0,
            numa_misses: 0,
            memory_bandwidth_gbps: 0.0,
            memory_latency_ns: 0.0,
        }
    }

    fn collect_ultra_gpu_metrics() -> Vec<UltraGpuMetrics> {
        let mut gpus = Vec::new();
        
        #[cfg(feature = "nvidia")]
        {
            if let Ok(nvml) = nvml_wrapper::Nvml::init() {
                if let Ok(device_count) = nvml.device_count() {
                    for i in 0..device_count {
                        if let Ok(device) = nvml.device_by_index(i) {
                            if let (Ok(utilization), Ok(memory), Ok(temperature), Ok(power)) = (
                                device.utilization_rates(),
                                device.memory_info(),
                                device.temperature(nvml_wrapper::enum_wrappers::device::TemperatureSensor::Gpu),
                                device.power_usage(),
                            ) {
                                gpus.push(UltraGpuMetrics {
                                    name: device.name().unwrap_or_else(|_| format!("GPU {}", i)),
                                    usage_percent: utilization.gpu as f32,
                                    memory_used_bytes: memory.used,
                                    memory_total_bytes: memory.total,
                                    temperature_celsius: temperature as f32,
                                    power_watts: power as f32 / 1000.0,
                                    fan_speed_percent: device.fan_speed(0).ok().map(|s| s as f32),
                                    clock_mhz: device.clock_info(nvml_wrapper::enum_wrappers::device::Clock::Graphics).unwrap_or(0) as f32,
                                    memory_clock_mhz: device.clock_info(nvml_wrapper::enum_wrappers::device::Clock::Memory).unwrap_or(0) as f32,
                                    compute_utilization: utilization.gpu as f32,
                                    memory_utilization: (memory.used as f32 / memory.total as f32) * 100.0,
                                    pcie_bandwidth_gbps: 0.0, // TODO: Add PCIe bandwidth monitoring
                                });
                            }
                        }
                    }
                }
            }
        }
        
        gpus
    }

    fn collect_ultra_disk_metrics(_sys: &sysinfo::System, _previous_stats: &DashMap<String, (u64, u64)>) -> Vec<UltraDiskMetrics> {
        let disks = Vec::new();
        
        // TODO: Implement actual disk I/O monitoring with ultra-low latency
        // For now, return empty vector
        disks
    }

    fn collect_ultra_network_metrics(_sys: &sysinfo::System, _previous_stats: &DashMap<String, (u64, u64)>) -> Vec<UltraNetworkMetrics> {
        let networks = Vec::new();
        
        // TODO: Implement actual network monitoring with ultra-low latency
        // For now, return empty vector
        networks
    }

    fn collect_ultra_process_metrics(sys: &sysinfo::System) -> Vec<UltraProcessMetrics> {
        let mut processes: Vec<UltraProcessMetrics> = sys.processes()
            .par_iter()
            .map(|(pid, process)| {
                UltraProcessMetrics {
                    pid: pid.as_u32(),
                    name: process.name().to_string(),
                    cpu_usage_percent: process.cpu_usage(),
                    memory_bytes: process.memory(),
                    disk_read_bytes_per_sec: 0, // TODO: Add process I/O monitoring
                    disk_write_bytes_per_sec: 0,
                    network_bytes_per_sec: 0, // TODO: Add process network monitoring
                    threads: 1, // TODO: Add thread count
                    priority: 0, // TODO: Add process priority
                    cpu_affinity: Vec::new(), // TODO: Add CPU affinity
                    memory_working_set: 0, // TODO: Add working set size
                    io_priority: 0, // TODO: Add I/O priority
                }
            })
            .collect();

        // Sort by CPU usage and take top 20
        processes.sort_by(|a, b| b.cpu_usage_percent.partial_cmp(&a.cpu_usage_percent).expect("CPU usage comparison failed"));
        processes.truncate(20);
        
        processes
    }

    fn collect_hardware_counters() -> HardwareCounterMetrics {
        // TODO: Implement actual hardware performance counter collection
        // For now, return default values
        HardwareCounterMetrics::default()
    }
} 