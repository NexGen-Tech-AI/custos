#!/bin/bash

echo "Testing Tauri Backend Directly..."
echo ""

# First, let's create a simple Rust test program to verify system detection works
cd /home/ubuntu/system-detection/src-tauri

cat > src/test_monitoring.rs << 'EOF'
mod monitoring;
use monitoring::{MonitoringService, SystemInfo};
use tokio;

#[tokio::main]
async fn main() {
    println!("Testing system monitoring...\n");
    
    let service = MonitoringService::new();
    
    // Test getting system info
    match service.get_system_info().await {
        Ok(info) => {
            println!("✓ System Info Retrieved Successfully!");
            println!("  Hostname: {}", info.hostname);
            println!("  OS: {} {}", info.os_name, info.os_version);
            println!("  CPU: {}", info.cpu_brand);
            println!("  Cores: {} physical, {} threads", info.cpu_cores, info.cpu_threads);
            println!("  Memory: {} GB", info.total_memory / 1024 / 1024 / 1024);
            println!("  Boot time: {}", info.boot_time);
        }
        Err(e) => {
            println!("✗ Failed to get system info: {}", e);
        }
    }
    
    // Test collecting metrics
    println!("\nTesting metrics collection...");
    match service.collect_metrics().await {
        Ok(metrics) => {
            println!("✓ Metrics Retrieved Successfully!");
            println!("  CPU Usage: {:.1}%", metrics.cpu.usage_percent);
            println!("  Memory Usage: {:.1}%", metrics.memory.usage_percent);
            println!("  Disk count: {}", metrics.disks.len());
            println!("  Network interfaces: {}", metrics.networks.len());
            println!("  Top processes: {}", metrics.top_processes.len());
        }
        Err(e) => {
            println!("✗ Failed to collect metrics: {}", e);
        }
    }
}
EOF

# Add a bin entry to Cargo.toml
echo '

[[bin]]
name = "test-monitoring"
path = "src/test_monitoring.rs"
' >> Cargo.toml

echo "Compiling test program..."
cargo build --bin test-monitoring 2>&1

echo ""
echo "Running test program..."
echo "================================"
./target/debug/test-monitoring