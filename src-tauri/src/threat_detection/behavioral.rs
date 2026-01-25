use super::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use chrono::Utc;

/// Behavioral analyzer for anomaly detection
pub struct BehavioralAnalyzer {
    baselines: Arc<Mutex<HashMap<String, BehavioralBaseline>>>,
    sensitivity: f64, // 0.0 - 1.0, higher = more sensitive
}

impl BehavioralAnalyzer {
    pub fn new(sensitivity: f64) -> Self {
        Self {
            baselines: Arc::new(Mutex::new(HashMap::new())),
            sensitivity: sensitivity.clamp(0.0, 1.0),
        }
    }

    /// Analyze a process for behavioral anomalies
    pub fn analyze_process(
        &self,
        process_name: &str,
        process_id: u32,
        process_path: &str,
        parent_process: Option<&str>,
        cpu_usage: f64,
        memory_usage: u64,
        network_connections: usize,
        file_operations: u64,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Get or create baseline
        let baseline = self.get_or_create_baseline(process_name);

        // Check for anomalies
        if let Some(threat) = self.check_cpu_anomaly(
            process_name,
            process_id,
            process_path,
            cpu_usage,
            &baseline,
        ) {
            threats.push(threat);
        }

        if let Some(threat) = self.check_memory_anomaly(
            process_name,
            process_id,
            process_path,
            memory_usage,
            &baseline,
        ) {
            threats.push(threat);
        }

        if let Some(threat) = self.check_parent_process_anomaly(
            process_name,
            process_id,
            process_path,
            parent_process,
            &baseline,
        ) {
            threats.push(threat);
        }

        // Specific suspicious behaviors
        threats.extend(self.check_suspicious_behaviors(
            process_name,
            process_id,
            process_path,
            parent_process,
            cpu_usage,
            memory_usage,
        ));

        // Update baseline if in learning mode
        self.update_baseline(
            process_name,
            cpu_usage,
            memory_usage,
            network_connections as u64,
            file_operations,
            parent_process,
        );

        threats
    }

    fn get_or_create_baseline(&self, process_name: &str) -> BehavioralBaseline {
        let mut baselines = self.baselines.lock().unwrap();

        baselines
            .entry(process_name.to_string())
            .or_insert_with(|| BehavioralBaseline {
                process_name: process_name.to_string(),
                normal_cpu_usage: 0.0,
                normal_memory_usage: 0,
                normal_network_activity: 0,
                normal_file_operations: 0,
                typical_parent_processes: Vec::new(),
                typical_child_processes: Vec::new(),
                first_seen: Utc::now(),
                last_updated: Utc::now(),
                observation_count: 0,
            })
            .clone()
    }

    fn check_cpu_anomaly(
        &self,
        process_name: &str,
        process_id: u32,
        process_path: &str,
        cpu_usage: f64,
        baseline: &BehavioralBaseline,
    ) -> Option<ThreatEvent> {
        if baseline.observation_count < 10 {
            return None; // Not enough data
        }

        // Calculate threshold based on sensitivity
        let threshold = baseline.normal_cpu_usage * (2.0 + (1.0 - self.sensitivity) * 3.0);

        if cpu_usage > threshold && cpu_usage > 50.0 {
            let deviation = ((cpu_usage - baseline.normal_cpu_usage) / baseline.normal_cpu_usage) * 100.0;

            return Some(ThreatEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                severity: if cpu_usage > 90.0 {
                    ThreatSeverity::High
                } else {
                    ThreatSeverity::Medium
                },
                category: ThreatCategory::Impact,
                title: format!("Abnormal CPU Usage: {}", process_name),
                description: format!(
                    "Process '{}' is using {:.1}% CPU, which is {:.1}% above normal baseline of {:.1}%",
                    process_name, cpu_usage, deviation, baseline.normal_cpu_usage
                ),
                detection_method: DetectionMethod::AnomalyDetection,
                process_id: Some(process_id),
                process_name: Some(process_name.to_string()),
                process_path: Some(process_path.to_string()),
                parent_process: None,
                user: None,
                network_connection: None,
                file_path: None,
                file_hash: None,
                ai_analysis: None,
                threat_intel: None,
                mitre_tactics: vec!["Impact".to_string()],
                mitre_techniques: vec!["T1496".to_string()], // Resource Hijacking
                confidence: self.calculate_confidence(deviation, baseline.observation_count),
                metadata: HashMap::from([
                    ("current_cpu".to_string(), cpu_usage.to_string()),
                    ("baseline_cpu".to_string(), baseline.normal_cpu_usage.to_string()),
                    ("deviation_percent".to_string(), deviation.to_string()),
                ]),
                recommended_actions: vec![
                    "Investigate process activity".to_string(),
                    "Check for cryptomining or DoS activity".to_string(),
                    "Review process legitimacy".to_string(),
                ],
                status: ThreatStatus::Active,
            });
        }

        None
    }

    fn check_memory_anomaly(
        &self,
        process_name: &str,
        process_id: u32,
        process_path: &str,
        memory_usage: u64,
        baseline: &BehavioralBaseline,
    ) -> Option<ThreatEvent> {
        if baseline.observation_count < 10 || baseline.normal_memory_usage == 0 {
            return None;
        }

        let threshold = baseline.normal_memory_usage as f64 * (2.0 + (1.0 - self.sensitivity) * 3.0);

        if memory_usage as f64 > threshold && memory_usage > 500_000_000 { // >500MB
            let deviation = ((memory_usage as f64 - baseline.normal_memory_usage as f64) / baseline.normal_memory_usage as f64) * 100.0;

            return Some(ThreatEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                severity: if memory_usage > 2_000_000_000 {
                    ThreatSeverity::High
                } else {
                    ThreatSeverity::Medium
                },
                category: ThreatCategory::Impact,
                title: format!("Abnormal Memory Usage: {}", process_name),
                description: format!(
                    "Process '{}' is using {} MB, which is {:.1}% above normal baseline of {} MB",
                    process_name,
                    memory_usage / 1_000_000,
                    deviation,
                    baseline.normal_memory_usage / 1_000_000
                ),
                detection_method: DetectionMethod::AnomalyDetection,
                process_id: Some(process_id),
                process_name: Some(process_name.to_string()),
                process_path: Some(process_path.to_string()),
                parent_process: None,
                user: None,
                network_connection: None,
                file_path: None,
                file_hash: None,
                ai_analysis: None,
                threat_intel: None,
                mitre_tactics: vec!["Impact".to_string()],
                mitre_techniques: vec!["T1499".to_string()], // Endpoint DoS
                confidence: self.calculate_confidence(deviation, baseline.observation_count),
                metadata: HashMap::from([
                    ("current_memory_mb".to_string(), (memory_usage / 1_000_000).to_string()),
                    ("baseline_memory_mb".to_string(), (baseline.normal_memory_usage / 1_000_000).to_string()),
                ]),
                recommended_actions: vec![
                    "Check for memory leaks".to_string(),
                    "Investigate data exfiltration attempts".to_string(),
                    "Monitor process for data collection".to_string(),
                ],
                status: ThreatStatus::Active,
            });
        }

        None
    }

    fn check_parent_process_anomaly(
        &self,
        process_name: &str,
        process_id: u32,
        process_path: &str,
        parent_process: Option<&str>,
        baseline: &BehavioralBaseline,
    ) -> Option<ThreatEvent> {
        if baseline.typical_parent_processes.is_empty() || parent_process.is_none() {
            return None;
        }

        let parent = parent_process.unwrap();

        // Check if this is an unusual parent
        if !baseline.typical_parent_processes.iter().any(|p| p == parent) {
            return Some(ThreatEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: Utc::now(),
                severity: ThreatSeverity::High,
                category: ThreatCategory::Execution,
                title: format!("Unusual Parent Process: {}", process_name),
                description: format!(
                    "Process '{}' was spawned by unusual parent '{}'. Typical parents: {}",
                    process_name,
                    parent,
                    baseline.typical_parent_processes.join(", ")
                ),
                detection_method: DetectionMethod::AnomalyDetection,
                process_id: Some(process_id),
                process_name: Some(process_name.to_string()),
                process_path: Some(process_path.to_string()),
                parent_process: Some(parent.to_string()),
                user: None,
                network_connection: None,
                file_path: None,
                file_hash: None,
                ai_analysis: None,
                threat_intel: None,
                mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                mitre_techniques: vec!["T1059".to_string()], // Command and Scripting Interpreter
                confidence: 0.8,
                metadata: HashMap::new(),
                recommended_actions: vec![
                    "Verify process legitimacy".to_string(),
                    "Check for process injection".to_string(),
                    "Investigate parent process".to_string(),
                ],
                status: ThreatStatus::Active,
            });
        }

        None
    }

    fn check_suspicious_behaviors(
        &self,
        process_name: &str,
        process_id: u32,
        process_path: &str,
        parent_process: Option<&str>,
        _cpu_usage: f64,
        _memory_usage: u64,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        // Check for suspicious process names
        let suspicious_patterns = [
            "mimikatz", "psexec", "procdump", "pwdump", "wce",
            "cain", "john", "hashcat", "metasploit", "meterpreter",
            "cobalt", "beacon", "empire", "covenant", "cryptominer",
        ];

        let process_lower = process_name.to_lowercase();
        for pattern in &suspicious_patterns {
            if process_lower.contains(pattern) {
                threats.push(ThreatEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    severity: ThreatSeverity::Critical,
                    category: ThreatCategory::Malware,
                    title: format!("Suspicious Process Detected: {}", process_name),
                    description: format!(
                        "Process name '{}' matches known malicious pattern '{}'",
                        process_name, pattern
                    ),
                    detection_method: DetectionMethod::Signature,
                    process_id: Some(process_id),
                    process_name: Some(process_name.to_string()),
                    process_path: Some(process_path.to_string()),
                    parent_process: parent_process.map(String::from),
                    user: None,
                    network_connection: None,
                    file_path: None,
                    file_hash: None,
                    ai_analysis: None,
                    threat_intel: None,
                    mitre_tactics: vec!["Execution".to_string(), "Credential Access".to_string()],
                    mitre_techniques: vec!["T1003".to_string()], // OS Credential Dumping
                    confidence: 0.95,
                    metadata: HashMap::from([
                        ("matched_pattern".to_string(), pattern.to_string()),
                    ]),
                    recommended_actions: vec![
                        "Immediately terminate process".to_string(),
                        "Isolate system from network".to_string(),
                        "Perform full system scan".to_string(),
                        "Change all credentials".to_string(),
                    ],
                    status: ThreatStatus::Active,
                });
                break;
            }
        }

        threats
    }

    fn update_baseline(
        &self,
        process_name: &str,
        cpu_usage: f64,
        memory_usage: u64,
        network_activity: u64,
        file_operations: u64,
        parent_process: Option<&str>,
    ) {
        let mut baselines = self.baselines.lock().unwrap();

        if let Some(baseline) = baselines.get_mut(process_name) {
            let count = baseline.observation_count as f64;

            // Exponential moving average
            baseline.normal_cpu_usage = (baseline.normal_cpu_usage * count + cpu_usage) / (count + 1.0);
            baseline.normal_memory_usage = ((baseline.normal_memory_usage as f64 * count + memory_usage as f64) / (count + 1.0)) as u64;
            baseline.normal_network_activity = ((baseline.normal_network_activity as f64 * count + network_activity as f64) / (count + 1.0)) as u64;
            baseline.normal_file_operations = ((baseline.normal_file_operations as f64 * count + file_operations as f64) / (count + 1.0)) as u64;

            // Track parent processes
            if let Some(parent) = parent_process {
                if !baseline.typical_parent_processes.contains(&parent.to_string()) && baseline.typical_parent_processes.len() < 5 {
                    baseline.typical_parent_processes.push(parent.to_string());
                }
            }

            baseline.last_updated = Utc::now();
            baseline.observation_count += 1;
        }
    }

    fn calculate_confidence(&self, deviation: f64, observations: u64) -> f64 {
        // Higher deviation = higher confidence
        // More observations = higher confidence
        let deviation_score = (deviation / 200.0).min(1.0); // Normalize to 0-1
        let observation_score = (observations as f64 / 100.0).min(1.0); // More observations = more confidence

        ((deviation_score * 0.7 + observation_score * 0.3) * 100.0).round() / 100.0
    }

    /// Export baselines for persistence
    pub fn export_baselines(&self) -> HashMap<String, BehavioralBaseline> {
        self.baselines.lock().unwrap().clone()
    }

    /// Import baselines from storage
    pub fn import_baselines(&self, baselines: HashMap<String, BehavioralBaseline>) {
        *self.baselines.lock().unwrap() = baselines;
    }
}
