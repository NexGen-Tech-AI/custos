use super::*;
use super::behavioral::BehavioralAnalyzer;
use super::signatures::SignatureDetector;
use super::ai_analyzer::{AIAnalyzer, HeuristicAnalyzer};
use super::threat_intel::{ThreatIntelService, LocalThreatIntel, ThreatIntelApiKeys};
use super::alerts::{AlertManager, AlertConfig};

use std::sync::Arc;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use chrono::Utc;

/// Main threat detection engine
pub struct ThreatDetectionEngine {
    config: ThreatDetectionConfig,

    // Detection modules
    behavioral_analyzer: Arc<BehavioralAnalyzer>,
    signature_detector: Arc<SignatureDetector>,
    ai_analyzer: Arc<AIAnalyzer>,
    heuristic_analyzer: Arc<HeuristicAnalyzer>,
    threat_intel: Arc<ThreatIntelService>,
    local_intel: Arc<RwLock<LocalThreatIntel>>,

    // Alert management
    alert_manager: Arc<AlertManager>,

    // Statistics
    stats: Arc<RwLock<ThreatStats>>,

    // Event channel
    event_tx: mpsc::UnboundedSender<ThreatEvent>,
    event_rx: Arc<RwLock<mpsc::UnboundedReceiver<ThreatEvent>>>,
}

impl ThreatDetectionEngine {
    pub fn new(
        config: ThreatDetectionConfig,
        claude_api_key: Option<String>,
        threat_intel_keys: ThreatIntelApiKeys,
    ) -> Self {
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            behavioral_analyzer: Arc::new(BehavioralAnalyzer::new(0.7)),
            signature_detector: Arc::new(SignatureDetector::new()),
            ai_analyzer: Arc::new(AIAnalyzer::new(claude_api_key)),
            heuristic_analyzer: Arc::new(HeuristicAnalyzer::new(0.5)),
            threat_intel: Arc::new(ThreatIntelService::new(threat_intel_keys)),
            local_intel: Arc::new(RwLock::new(LocalThreatIntel::new())),
            alert_manager: Arc::new(AlertManager::new(AlertConfig::default())),
            stats: Arc::new(RwLock::new(ThreatStats::default())),
            config,
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
        }
    }

    /// Scan a process for threats
    pub async fn scan_process(
        &self,
        process_name: &str,
        process_path: &str,
        process_id: u32,
        parent_process: Option<&str>,
        command_line: Option<&str>,
        cpu_usage: f64,
        memory_usage: u64,
        network_connections: usize,
        file_operations: u64,
    ) -> Vec<ThreatEvent> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut threats = Vec::new();

        // 1. Signature-based detection
        if self.config.signature_detection {
            let sig_threats = self.signature_detector.scan_process(
                process_name,
                process_path,
                process_id,
                parent_process,
                command_line,
            );
            threats.extend(sig_threats);
        }

        // 2. Behavioral analysis
        if self.config.behavioral_detection {
            let beh_threats = self.behavioral_analyzer.analyze_process(
                process_name,
                process_id,
                process_path,
                parent_process,
                cpu_usage,
                memory_usage,
                network_connections,
                file_operations,
            );
            threats.extend(beh_threats);
        }

        // 3. Heuristic analysis
        let heur_threats = self.heuristic_analyzer.analyze_process(
            process_name,
            process_path,
            process_id,
            parent_process,
            command_line,
            cpu_usage,
            memory_usage,
            network_connections,
            file_operations,
        );
        threats.extend(heur_threats);

        // 4. AI Analysis (for high-confidence threats)
        if self.config.ai_analysis && !threats.is_empty() {
            for threat in &mut threats {
                if threat.confidence > 0.7 {
                    if let Some(ai_analysis) = self.ai_analyzer.analyze_threat(threat).await {
                        threat.ai_analysis = Some(ai_analysis);
                    }
                }
            }
        }

        // 5. Process threats and send alerts
        for threat in &threats {
            self.process_threat(threat.clone()).await;
        }

        threats
    }

    /// Scan file operation for threats
    pub async fn scan_file_operation(
        &self,
        file_path: &str,
        file_hash: Option<&str>,
        operation: &str,
        process_name: &str,
        process_id: u32,
    ) -> Vec<ThreatEvent> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut threats = Vec::new();

        // Signature-based file detection
        if self.config.signature_detection {
            let file_threats = self.signature_detector.scan_file(
                file_path,
                file_hash,
                operation,
                process_name,
                process_id,
            );
            threats.extend(file_threats);
        }

        // Check file hash against threat intelligence
        if self.config.threat_intel {
            if let Some(hash) = file_hash {
                // Check local intel first
                if let Some(malware_name) = self.local_intel.read().is_malicious_hash(hash) {
                    threats.push(ThreatEvent {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: Utc::now(),
                        severity: ThreatSeverity::Critical,
                        category: ThreatCategory::Malware,
                        title: format!("Known Malware Detected: {}", malware_name),
                        description: format!("File hash {} matches known malware: {}", hash, malware_name),
                        detection_method: DetectionMethod::ThreatIntel,
                        process_id: Some(process_id),
                        process_name: Some(process_name.to_string()),
                        process_path: None,
                        parent_process: None,
                        user: None,
                        network_connection: None,
                        file_path: Some(file_path.to_string()),
                        file_hash: Some(hash.to_string()),
                        ai_analysis: None,
                        threat_intel: None,
                        mitre_tactics: vec!["Execution".to_string()],
                        mitre_techniques: vec!["T1204".to_string()],
                        confidence: 0.99,
                        metadata: std::collections::HashMap::new(),
                        recommended_actions: vec![
                            "Immediately quarantine file".to_string(),
                            "Terminate associated process".to_string(),
                            "Perform full system scan".to_string(),
                        ],
                        status: ThreatStatus::Active,
                    });
                }

                // Check external threat intelligence
                if let Some(intel) = self.threat_intel.check_file_hash(hash).await {
                    if intel.reputation_score > 0.7 {
                        threats.push(ThreatEvent {
                            id: uuid::Uuid::new_v4().to_string(),
                            timestamp: Utc::now(),
                            severity: if intel.reputation_score > 0.9 {
                                ThreatSeverity::Critical
                            } else {
                                ThreatSeverity::High
                            },
                            category: ThreatCategory::Malware,
                            title: "File Hash Flagged by Threat Intelligence".to_string(),
                            description: format!("File hash flagged by {}", intel.source),
                            detection_method: DetectionMethod::ThreatIntel,
                            process_id: Some(process_id),
                            process_name: Some(process_name.to_string()),
                            process_path: None,
                            parent_process: None,
                            user: None,
                            network_connection: None,
                            file_path: Some(file_path.to_string()),
                            file_hash: Some(hash.to_string()),
                            ai_analysis: None,
                            threat_intel: Some(intel),
                            mitre_tactics: vec!["Execution".to_string()],
                            mitre_techniques: vec!["T1204".to_string()],
                            confidence: 0.90,
                            metadata: std::collections::HashMap::new(),
                            recommended_actions: vec![
                                "Quarantine file".to_string(),
                                "Investigate process".to_string(),
                            ],
                            status: ThreatStatus::Active,
                        });
                    }
                }
            }
        }

        // Process threats
        for threat in &threats {
            self.process_threat(threat.clone()).await;
        }

        threats
    }

    /// Scan network connection for threats
    pub async fn scan_network_connection(
        &self,
        remote_address: &str,
        remote_port: u16,
        protocol: &str,
        process_name: &str,
        process_id: u32,
    ) -> Vec<ThreatEvent> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut threats = Vec::new();

        // Signature-based network detection
        if self.config.signature_detection {
            let net_threats = self.signature_detector.scan_network(
                remote_address,
                remote_port,
                protocol,
                process_name,
                process_id,
            );
            threats.extend(net_threats);
        }

        // Check IP reputation
        if self.config.threat_intel {
            // Check local intel
            if let Some(threat_name) = self.local_intel.read().is_malicious_ip(remote_address) {
                threats.push(ThreatEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: Utc::now(),
                    severity: ThreatSeverity::High,
                    category: ThreatCategory::CommandAndControl,
                    title: format!("Connection to Known Malicious IP: {}", threat_name),
                    description: format!("Process connecting to known malicious IP: {}", remote_address),
                    detection_method: DetectionMethod::ThreatIntel,
                    process_id: Some(process_id),
                    process_name: Some(process_name.to_string()),
                    process_path: None,
                    parent_process: None,
                    user: None,
                    network_connection: Some(NetworkContext {
                        local_address: "0.0.0.0".to_string(),
                        local_port: 0,
                        remote_address: remote_address.to_string(),
                        remote_port,
                        protocol: protocol.to_string(),
                        bytes_sent: 0,
                        bytes_received: 0,
                    }),
                    file_path: None,
                    file_hash: None,
                    ai_analysis: None,
                    threat_intel: None,
                    mitre_tactics: vec!["Command and Control".to_string()],
                    mitre_techniques: vec!["T1071".to_string()],
                    confidence: 0.95,
                    metadata: std::collections::HashMap::new(),
                    recommended_actions: vec![
                        "Block IP address".to_string(),
                        "Terminate process".to_string(),
                        "Investigate system compromise".to_string(),
                    ],
                    status: ThreatStatus::Active,
                });
            }

            // Check external threat intelligence
            if let Some(intel) = self.threat_intel.check_ip_reputation(remote_address).await {
                if intel.reputation_score > 0.7 {
                    threats.push(ThreatEvent {
                        id: uuid::Uuid::new_v4().to_string(),
                        timestamp: Utc::now(),
                        severity: if intel.reputation_score > 0.9 {
                            ThreatSeverity::Critical
                        } else {
                            ThreatSeverity::High
                        },
                        category: ThreatCategory::CommandAndControl,
                        title: "Suspicious IP Connection".to_string(),
                        description: format!("Connection to IP flagged by {}", intel.source),
                        detection_method: DetectionMethod::ThreatIntel,
                        process_id: Some(process_id),
                        process_name: Some(process_name.to_string()),
                        process_path: None,
                        parent_process: None,
                        user: None,
                        network_connection: Some(NetworkContext {
                            local_address: "0.0.0.0".to_string(),
                            local_port: 0,
                            remote_address: remote_address.to_string(),
                            remote_port,
                            protocol: protocol.to_string(),
                            bytes_sent: 0,
                            bytes_received: 0,
                        }),
                        file_path: None,
                        file_hash: None,
                        ai_analysis: None,
                        threat_intel: Some(intel),
                        mitre_tactics: vec!["Command and Control".to_string()],
                        mitre_techniques: vec!["T1071".to_string()],
                        confidence: 0.85,
                        metadata: std::collections::HashMap::new(),
                        recommended_actions: vec![
                            "Monitor connection".to_string(),
                            "Investigate process".to_string(),
                        ],
                        status: ThreatStatus::Active,
                    });
                }
            }
        }

        // Process threats
        for threat in &threats {
            self.process_threat(threat.clone()).await;
        }

        threats
    }

    /// Process a detected threat
    async fn process_threat(&self, threat: ThreatEvent) {
        // Update statistics
        {
            let mut stats = self.stats.write();
            stats.total_threats += 1;
            stats.by_severity.entry(format!("{:?}", threat.severity))
                .and_modify(|c| *c += 1)
                .or_insert(1);
            stats.by_category.entry(format!("{:?}", threat.category))
                .and_modify(|c| *c += 1)
                .or_insert(1);
        }

        // Send to alert manager
        self.alert_manager.process_threat(threat.clone()).await;

        // Send to event channel
        let _ = self.event_tx.send(threat);
    }

    /// Get threat statistics
    pub fn get_statistics(&self) -> ThreatStats {
        self.stats.read().clone()
    }

    /// Get recent threats
    pub fn get_recent_threats(&self, limit: usize) -> Vec<ThreatEvent> {
        self.alert_manager
            .get_alerts()
            .into_iter()
            .take(limit)
            .map(|a| a.threat_event)
            .collect()
    }

    /// Get alert manager
    pub fn get_alert_manager(&self) -> Arc<AlertManager> {
        Arc::clone(&self.alert_manager)
    }

    /// Export behavioral baselines
    pub fn export_baselines(&self) -> std::collections::HashMap<String, BehavioralBaseline> {
        self.behavioral_analyzer.export_baselines()
    }

    /// Import behavioral baselines
    pub fn import_baselines(&self, baselines: std::collections::HashMap<String, BehavioralBaseline>) {
        self.behavioral_analyzer.import_baselines(baselines);
    }

    /// Update threat intelligence
    pub fn update_threat_intelligence(&self) {
        self.local_intel.write().update();
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ThreatStats {
    pub total_threats: usize,
    pub by_severity: std::collections::HashMap<String, usize>,
    pub by_category: std::collections::HashMap<String, usize>,
}
