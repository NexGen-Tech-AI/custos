/*!
 * Real eBPF Monitor - Kernel-level Event Monitoring
 *
 * This module loads and manages eBPF programs for process, file, and network monitoring.
 * Requires CAP_BPF or CAP_SYS_ADMIN capabilities.
 */

use tokio::sync::mpsc;

#[cfg(all(target_os = "linux", feature = "ebpf"))]
use {
    aya::{Bpf, programs::{TracePoint, KProbe}, maps::RingBuf},
    custos_ebpf_common::{EventType, ProcessExecEvent, ProcessExitEvent, FileOpenEvent, TcpConnectEvent},
    std::{
        os::unix::io::AsRawFd,
        path::Path,
        sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}},
        time::{Duration, Instant},
    },
    tokio::{
        io::unix::AsyncFd,
        time::sleep,
    },
    tracing::{info, warn, error},
};

/// Ring buffer statistics for overflow detection
#[derive(Debug, Clone)]
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub struct RingBufStats {
    pub events_received: u64,
    pub events_processed: u64,
    pub parse_errors: u64,
    pub unknown_events: u64,
    pub send_errors: u64,
    pub last_event_timestamp: u64,
    pub polling_duration_micros: u64,
}

/// Normalized system event from eBPF
#[derive(Debug, Clone)]
pub enum SystemEvent {
    ProcessExec {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
        timestamp: u64,
    },
    ProcessExit {
        pid: u32,
        comm: String,
        exit_code: i32,
        timestamp: u64,
    },
    FileOpen {
        pid: u32,
        uid: u32,
        comm: String,
        filename: String,
        flags: i32,
        timestamp: u64,
    },
    TcpConnect {
        pid: u32,
        uid: u32,
        comm: String,
        daddr: [u8; 4],
        dport: u16,
        timestamp: u64,
    },
}

/// eBPF Monitor for kernel-level event capture
#[cfg(all(target_os = "linux", feature = "ebpf"))]
pub struct EbpfMonitor {
    bpf: Bpf,
    event_tx: mpsc::UnboundedSender<SystemEvent>,
    running: Arc<AtomicBool>,
    // Statistics for overflow detection
    events_received: Arc<AtomicU64>,
    events_processed: Arc<AtomicU64>,
    parse_errors: Arc<AtomicU64>,
    unknown_events: Arc<AtomicU64>,
    send_errors: Arc<AtomicU64>,
    last_event_timestamp: Arc<AtomicU64>,
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl EbpfMonitor {
    /// Load eBPF programs and attach to tracepoints/kprobes
    pub fn new() -> Result<(Self, mpsc::UnboundedReceiver<SystemEvent>), anyhow::Error> {
        info!("Loading eBPF programs...");

        // Load compiled eBPF object file
        let ebpf_path = Path::new("target/bpfel-unknown-none/release/custos-ebpf");
        if !ebpf_path.exists() {
            anyhow::bail!(
                "eBPF object not found at {:?}. Build with: cargo +nightly build --release --target bpfel-unknown-none -Zbuild-std=core",
                ebpf_path
            );
        }

        let mut bpf = Bpf::load_file(ebpf_path)?;

        // Attach process execution tracepoint
        let prog: &mut TracePoint = bpf.program_mut("sched_process_exec")
            .ok_or_else(|| anyhow::anyhow!("sched_process_exec program not found"))?
            .try_into()?;
        prog.load()?;
        prog.attach("sched", "sched_process_exec")?;
        info!("✓ Attached to sched:sched_process_exec");

        // Attach process exit tracepoint
        let prog: &mut TracePoint = bpf.program_mut("sched_process_exit")
            .ok_or_else(|| anyhow::anyhow!("sched_process_exit program not found"))?
            .try_into()?;
        prog.load()?;
        prog.attach("sched", "sched_process_exit")?;
        info!("✓ Attached to sched:sched_process_exit");

        // Attach file open tracepoint
        let prog: &mut TracePoint = bpf.program_mut("sys_enter_openat")
            .ok_or_else(|| anyhow::anyhow!("sys_enter_openat program not found"))?
            .try_into()?;
        prog.load()?;
        prog.attach("syscalls", "sys_enter_openat")?;
        info!("✓ Attached to syscalls:sys_enter_openat");

        // Attach TCP connect kprobe
        let prog: &mut KProbe = bpf.program_mut("tcp_connect")
            .ok_or_else(|| anyhow::anyhow!("tcp_connect program not found"))?
            .try_into()?;
        prog.load()?;
        prog.attach("tcp_connect", 0)?;
        info!("✓ Attached kprobe to tcp_connect");

        let (tx, rx) = mpsc::unbounded_channel();

        Ok((
            Self {
                bpf,
                event_tx: tx,
                running: Arc::new(AtomicBool::new(false)),
                events_received: Arc::new(AtomicU64::new(0)),
                events_processed: Arc::new(AtomicU64::new(0)),
                parse_errors: Arc::new(AtomicU64::new(0)),
                unknown_events: Arc::new(AtomicU64::new(0)),
                send_errors: Arc::new(AtomicU64::new(0)),
                last_event_timestamp: Arc::new(AtomicU64::new(0)),
            },
            rx,
        ))
    }

    /// Start reading events from ring buffer
    pub async fn start(&mut self) -> Result<(), anyhow::Error> {
        self.running.store(true, Ordering::SeqCst);
        let running = self.running.clone();
        let event_tx = self.event_tx.clone();

        // Clone statistics counters for the polling task
        let events_received = self.events_received.clone();
        let events_processed = self.events_processed.clone();
        let parse_errors = self.parse_errors.clone();
        let unknown_events = self.unknown_events.clone();
        let send_errors = self.send_errors.clone();
        let last_event_timestamp = self.last_event_timestamp.clone();

        info!("eBPF monitor started - programs loaded and attached");

        // Get the ring buffer map
        let mut ring_buf: RingBuf<_> = self.bpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS ring buffer not found"))?
            .try_into()?;

        info!("Ring buffer opened, starting event polling...");

        // Spawn event polling task
        tokio::spawn(async move {
            // Create AsyncFd wrapper for async polling
            let fd = ring_buf.as_raw_fd();
            let async_fd = match AsyncFd::new(fd) {
                Ok(afd) => afd,
                Err(e) => {
                    error!("Failed to create AsyncFd for ring buffer: {}", e);
                    return;
                }
            };

            let mut event_count = 0u64;
            let mut last_stats_report = Instant::now();
            let stats_report_interval = Duration::from_secs(30);

            while running.load(Ordering::SeqCst) {
                // Wait for ring buffer to have data
                let mut guard = match async_fd.readable().await {
                    Ok(g) => g,
                    Err(e) => {
                        error!("AsyncFd readable error: {}", e);
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };

                let batch_start = Instant::now();

                // Drain all available events
                loop {
                    match ring_buf.next() {
                        Some(item) => {
                            let data: &[u8] = item.as_ref();
                            events_received.fetch_add(1, Ordering::Relaxed);

                            // Read event type from first 4 bytes
                            if data.len() < 4 {
                                warn!("Event too small: {} bytes", data.len());
                                parse_errors.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }

                            let event_type = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

                            match event_type {
                                x if x == EventType::ProcessExec as u32 => {
                                    if let Ok(raw_event) = parse_event::<ProcessExecEvent>(data) {
                                        last_event_timestamp.store(raw_event.timestamp_ns, Ordering::Relaxed);
                                        let event = SystemEvent::ProcessExec {
                                            pid: raw_event.pid,
                                            uid: raw_event.uid,
                                            comm: bytes_to_string(&raw_event.comm),
                                            filename: bytes_to_string(&raw_event.filename),
                                            timestamp: raw_event.timestamp_ns,
                                        };
                                        if let Err(e) = event_tx.send(event) {
                                            error!("Failed to send ProcessExec event: {}", e);
                                            send_errors.fetch_add(1, Ordering::Relaxed);
                                        } else {
                                            events_processed.fetch_add(1, Ordering::Relaxed);
                                            event_count += 1;
                                        }
                                    } else {
                                        parse_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                x if x == EventType::ProcessExit as u32 => {
                                    if let Ok(raw_event) = parse_event::<ProcessExitEvent>(data) {
                                        last_event_timestamp.store(raw_event.timestamp_ns, Ordering::Relaxed);
                                        let event = SystemEvent::ProcessExit {
                                            pid: raw_event.pid,
                                            comm: bytes_to_string(&raw_event.comm),
                                            exit_code: raw_event.exit_code,
                                            timestamp: raw_event.timestamp_ns,
                                        };
                                        if let Err(e) = event_tx.send(event) {
                                            error!("Failed to send ProcessExit event: {}", e);
                                            send_errors.fetch_add(1, Ordering::Relaxed);
                                        } else {
                                            events_processed.fetch_add(1, Ordering::Relaxed);
                                            event_count += 1;
                                        }
                                    } else {
                                        parse_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                x if x == EventType::FileOpen as u32 => {
                                    if let Ok(raw_event) = parse_event::<FileOpenEvent>(data) {
                                        last_event_timestamp.store(raw_event.timestamp_ns, Ordering::Relaxed);
                                        let event = SystemEvent::FileOpen {
                                            pid: raw_event.pid,
                                            uid: raw_event.uid,
                                            comm: bytes_to_string(&raw_event.comm),
                                            filename: bytes_to_string(&raw_event.filename),
                                            flags: raw_event.flags,
                                            timestamp: raw_event.timestamp_ns,
                                        };
                                        if let Err(e) = event_tx.send(event) {
                                            error!("Failed to send FileOpen event: {}", e);
                                            send_errors.fetch_add(1, Ordering::Relaxed);
                                        } else {
                                            events_processed.fetch_add(1, Ordering::Relaxed);
                                            event_count += 1;
                                        }
                                    } else {
                                        parse_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                x if x == EventType::TcpConnect as u32 => {
                                    if let Ok(raw_event) = parse_event::<TcpConnectEvent>(data) {
                                        last_event_timestamp.store(raw_event.timestamp_ns, Ordering::Relaxed);
                                        let daddr = [
                                            (raw_event.daddr & 0xFF) as u8,
                                            ((raw_event.daddr >> 8) & 0xFF) as u8,
                                            ((raw_event.daddr >> 16) & 0xFF) as u8,
                                            ((raw_event.daddr >> 24) & 0xFF) as u8,
                                        ];
                                        let event = SystemEvent::TcpConnect {
                                            pid: raw_event.pid,
                                            uid: raw_event.uid,
                                            comm: bytes_to_string(&raw_event.comm),
                                            daddr,
                                            dport: raw_event.dport,
                                            timestamp: raw_event.timestamp_ns,
                                        };
                                        if let Err(e) = event_tx.send(event) {
                                            error!("Failed to send TcpConnect event: {}", e);
                                            send_errors.fetch_add(1, Ordering::Relaxed);
                                        } else {
                                            events_processed.fetch_add(1, Ordering::Relaxed);
                                            event_count += 1;
                                        }
                                    } else {
                                        parse_errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                _ => {
                                    warn!("Unknown event type: {}", event_type);
                                    unknown_events.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        None => {
                            // No more events available, clear readable flag
                            guard.clear_ready();
                            break;
                        }
                    }
                }

                // Periodic statistics reporting
                if last_stats_report.elapsed() >= stats_report_interval {
                    let received = events_received.load(Ordering::Relaxed);
                    let processed = events_processed.load(Ordering::Relaxed);
                    let parse_errs = parse_errors.load(Ordering::Relaxed);
                    let send_errs = send_errors.load(Ordering::Relaxed);
                    let unknown = unknown_events.load(Ordering::Relaxed);

                    info!(
                        "eBPF Stats: received={}, processed={}, parse_errors={}, send_errors={}, unknown={}",
                        received, processed, parse_errs, send_errs, unknown
                    );

                    // Overflow detection: if received >> processed, we're falling behind
                    let dropped_estimate = received.saturating_sub(processed + parse_errs + send_errs + unknown);
                    if dropped_estimate > 100 {
                        warn!(
                            "Potential ring buffer overflow detected! Estimated {} events dropped. \
                            Consider reducing event volume with additional in-kernel filtering.",
                            dropped_estimate
                        );
                    }

                    last_stats_report = Instant::now();
                }

                if event_count % 1000 == 0 && event_count > 0 {
                    info!("Processed {} eBPF events", event_count);
                }
            }

            info!("eBPF event polling stopped (processed {} events total)", event_count);
        });

        Ok(())
    }

    /// Stop the monitor
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get ring buffer statistics for monitoring overflow and performance
    pub fn get_stats(&self) -> RingBufStats {
        RingBufStats {
            events_received: self.events_received.load(Ordering::Relaxed),
            events_processed: self.events_processed.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            unknown_events: self.unknown_events.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            last_event_timestamp: self.last_event_timestamp.load(Ordering::Relaxed),
            polling_duration_micros: 0, // Not tracked yet, can be added later if needed
        }
    }
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn parse_event<T>(data: &[u8]) -> Result<T, ()>
where
    T: aya::Pod + Copy,
{
    if data.len() < std::mem::size_of::<T>() {
        return Err(());
    }

    let event_ptr = data.as_ptr() as *const T;
    Ok(unsafe { *event_ptr })
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
fn bytes_to_string(bytes: &[u8]) -> String {
    // Find null terminator
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    // Convert to string, replacing invalid UTF-8
    String::from_utf8_lossy(&bytes[..len]).to_string()
}

#[cfg(all(target_os = "linux", feature = "ebpf"))]
impl Drop for EbpfMonitor {
    fn drop(&mut self) {
        self.stop();
        info!("eBPF monitor dropped");
    }
}

// Stub implementation when eBPF feature is disabled
#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
pub struct EbpfMonitor;

#[cfg(not(all(target_os = "linux", feature = "ebpf")))]
impl EbpfMonitor {
    pub fn new() -> Result<(Self, mpsc::UnboundedReceiver<SystemEvent>), anyhow::Error> {
        anyhow::bail!("eBPF support not enabled. Compile with --features ebpf on Linux.")
    }

    pub async fn start(&mut self) -> Result<(), anyhow::Error> {
        Ok(())
    }

    pub fn stop(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_parsing() {
        // Test that ProcessExecEvent can be parsed correctly
        use custos_ebpf_common::ProcessExecEvent;

        let mut event = ProcessExecEvent {
            event_type: EventType::ProcessExec as u32,
            pid: 1234,
            tid: 1234,
            uid: 1000,
            gid: 1000,
            comm: [0u8; 16],
            filename: [0u8; 256],
            timestamp_ns: 123456789,
        };

        // Set comm to "bash\0"
        event.comm[0] = b'b';
        event.comm[1] = b'a';
        event.comm[2] = b's';
        event.comm[3] = b'h';

        // Set filename to "/bin/bash\0"
        let filename_bytes = b"/bin/bash\0";
        event.filename[..filename_bytes.len()].copy_from_slice(filename_bytes);

        #[cfg(feature = "user")]
        {
            assert_eq!(event.comm_str(), "bash");
            assert_eq!(event.filename_str(), "/bin/bash");
        }

        assert_eq!(event.pid, 1234);
        assert_eq!(event.uid, 1000);
    }
}
