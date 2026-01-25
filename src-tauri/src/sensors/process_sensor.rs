// Process Sensor - monitors process creation, termination, and access

use super::*;
use sysinfo::System;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use parking_lot::Mutex;
use std::path::PathBuf;

pub struct ProcessSensor {
    running: bool,
    system: Arc<Mutex<System>>,
    known_processes: Arc<Mutex<HashSet<u32>>>,
    events: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl ProcessSensor {
    #[cfg(target_os = "linux")]
    pub fn new_linux() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            system: Arc::new(Mutex::new(System::new_all())),
            known_processes: Arc::new(Mutex::new(HashSet::new())),
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[cfg(target_os = "windows")]
    pub fn new_windows() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            system: Arc::new(Mutex::new(System::new_all())),
            known_processes: Arc::new(Mutex::new(HashSet::new())),
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[cfg(target_os = "macos")]
    pub fn new_macos() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            running: false,
            system: Arc::new(Mutex::new(System::new_all())),
            known_processes: Arc::new(Mutex::new(HashSet::new())),
            events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Poll for process changes
    fn poll_processes(&self) {
        let mut system = self.system.lock();
        system.refresh_processes();

        let mut known = self.known_processes.lock();
        let current_pids: HashSet<u32> = system
            .processes()
            .keys()
            .map(|pid| pid.as_u32())
            .collect();

        // Detect new processes
        for pid in current_pids.iter() {
            if !known.contains(pid) {
                if let Some(process) = system.process(sysinfo::Pid::from_u32(*pid)) {
                    let event = self.create_process_created_event(process);
                    self.events.lock().push(event);
                }
                known.insert(*pid);
            }
        }

        // Detect terminated processes
        let terminated: Vec<u32> = known
            .iter()
            .filter(|pid| !current_pids.contains(pid))
            .copied()
            .collect();

        for pid in terminated {
            let event = self.create_process_terminated_event(pid);
            self.events.lock().push(event);
            known.remove(&pid);
        }
    }

    /// Create ProcessCreated event
    fn create_process_created_event(&self, process: &sysinfo::Process) -> SecurityEvent {
        let pid = process.pid().as_u32();
        let name = process.name().to_string();
        let path = process.exe().map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let parent_pid = process.parent().map(|p| p.as_u32());
        let command_line = process.cmd().join(" ");

        let mut event = SecurityEvent::new(EventType::ProcessCreated);
        event.severity = EventSeverity::Info;

        // Build process context
        let mut process_ctx = ProcessContext {
            pid,
            name: name.clone(),
            path: path.clone(),
            command_line: if command_line.is_empty() {
                None
            } else {
                Some(command_line.clone())
            },
            parent_pid,
            parent_name: None,
            parent_path: None,
            user: process.user_id().map(|u| u.to_string()),
            integrity_level: None,
            hash_sha256: None,
            hash_md5: None,
            signer: None,
            signed: None,
        };

        // Get parent process info
        if let Some(ppid) = parent_pid {
            let system = self.system.lock();
            if let Some(parent) = system.process(sysinfo::Pid::from_u32(ppid)) {
                process_ctx.parent_name = Some(parent.name().to_string());
                process_ctx.parent_path = parent.exe()
                    .map(|p| p.to_string_lossy().to_string());
            }
        }

        // Calculate file hash if possible
        if let Ok(path_buf) = PathBuf::from(&path).canonicalize() {
            process_ctx.hash_sha256 = super::events::calculate_file_hash(&path_buf);
        }

        // Add tags
        event.add_tag("process");
        event.add_tag("process_creation");

        // Check for suspicious patterns
        if name.to_lowercase().contains("powershell") {
            event.add_tag("powershell");
            event.severity = EventSeverity::Medium;
        }

        if command_line.contains("-enc") || command_line.contains("EncodedCommand") {
            event.add_tag("encoded_command");
            event.severity = EventSeverity::High;
            event.set_mitre(
                vec!["Execution".to_string(), "Defense Evasion".to_string()],
                vec!["T1059.001".to_string(), "T1027".to_string()],
            );
        }

        // Check for suspicious parent-child relationships
        if let Some(parent_name) = &process_ctx.parent_name {
            let parent_lower = parent_name.to_lowercase();
            let name_lower = name.to_lowercase();

            // Office spawning shells
            if (parent_lower.contains("winword") ||
                parent_lower.contains("excel") ||
                parent_lower.contains("powerpnt")) &&
               (name_lower.contains("cmd") ||
                name_lower.contains("powershell") ||
                name_lower.contains("wscript")) {
                event.add_tag("suspicious_parent");
                event.severity = EventSeverity::High;
                event.set_mitre(
                    vec!["Execution".to_string()],
                    vec!["T1204".to_string()],
                );
            }
        }

        // Move process context into event (must be last since it consumes process_ctx)
        event.process = Some(process_ctx);

        event
    }

    /// Create ProcessTerminated event
    fn create_process_terminated_event(&self, pid: u32) -> SecurityEvent {
        let mut event = SecurityEvent::new(EventType::ProcessTerminated);
        event.severity = EventSeverity::Info;

        event.process = Some(ProcessContext {
            pid,
            name: "unknown".to_string(),
            path: "unknown".to_string(),
            command_line: None,
            parent_pid: None,
            parent_name: None,
            parent_path: None,
            user: None,
            integrity_level: None,
            hash_sha256: None,
            hash_md5: None,
            signer: None,
            signed: None,
        });

        event.add_tag("process");
        event.add_tag("process_termination");

        event
    }
}

#[async_trait::async_trait]
impl EventCollector for ProcessSensor {
    async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.running = true;

        // Initialize known processes
        let mut system = self.system.lock();
        system.refresh_processes();

        let mut known = self.known_processes.lock();
        for pid in system.processes().keys() {
            known.insert(pid.as_u32());
        }

        drop(system);
        drop(known);

        // Start background polling
        let system = Arc::clone(&self.system);
        let known_processes = Arc::clone(&self.known_processes);
        let events = Arc::clone(&self.events);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(2));

            loop {
                interval.tick().await;

                let mut sys = system.lock();
                sys.refresh_processes();

                let mut known = known_processes.lock();
                let current_pids: HashSet<u32> = sys
                    .processes()
                    .keys()
                    .map(|pid| pid.as_u32())
                    .collect();

                // Detect new processes
                for pid in current_pids.iter() {
                    if !known.contains(pid) {
                        if let Some(process) = sys.process(sysinfo::Pid::from_u32(*pid)) {
                            // Create event (simplified for background task)
                            let mut event = SecurityEvent::new(EventType::ProcessCreated);
                            event.process = Some(ProcessContext {
                                pid: *pid,
                                name: process.name().to_string(),
                                path: process.exe()
                                    .map(|p| p.to_string_lossy().to_string())
                                    .unwrap_or_else(|| "unknown".to_string()),
                                command_line: Some(process.cmd().join(" ")),
                                parent_pid: process.parent().map(|p| p.as_u32()),
                                parent_name: None,
                                parent_path: None,
                                user: process.user_id().map(|u| u.to_string()),
                                integrity_level: None,
                                hash_sha256: None,
                                hash_md5: None,
                                signer: None,
                                signed: None,
                            });

                            events.lock().push(event);
                        }
                        known.insert(*pid);
                    }
                }

                // Detect terminated processes
                let terminated: Vec<u32> = known
                    .iter()
                    .filter(|pid| !current_pids.contains(pid))
                    .copied()
                    .collect();

                for pid in terminated {
                    let mut event = SecurityEvent::new(EventType::ProcessTerminated);
                    event.process = Some(ProcessContext {
                        pid,
                        name: "unknown".to_string(),
                        path: "unknown".to_string(),
                        command_line: None,
                        parent_pid: None,
                        parent_name: None,
                        parent_path: None,
                        user: None,
                        integrity_level: None,
                        hash_sha256: None,
                        hash_md5: None,
                        signer: None,
                        signed: None,
                    });

                    events.lock().push(event);
                    known.remove(&pid);
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) {
        self.running = false;
    }

    async fn collect_events(&mut self) -> Vec<SecurityEvent> {
        let mut events = self.events.lock();
        let collected = events.drain(..).collect();
        collected
    }

    fn is_running(&self) -> bool {
        self.running
    }
}
