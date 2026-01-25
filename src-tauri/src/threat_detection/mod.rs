pub mod engine;
pub mod behavioral;
pub mod signatures;
pub mod ai_analyzer;
pub mod threat_intel;
pub mod alerts;

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Threat severity levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Threat categories based on MITRE ATT&CK
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatCategory {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
    Malware,
    Ransomware,
    Rootkit,
    Unknown,
}

/// Detection method used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DetectionMethod {
    Behavioral,
    Signature,
    Heuristic,
    AIAnalysis,
    ThreatIntel,
    AnomalyDetection,
    Hybrid(Vec<String>),
}

/// Threat detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: ThreatSeverity,
    pub category: ThreatCategory,
    pub title: String,
    pub description: String,
    pub detection_method: DetectionMethod,

    // Context
    pub process_id: Option<u32>,
    pub process_name: Option<String>,
    pub process_path: Option<String>,
    pub parent_process: Option<String>,
    pub user: Option<String>,

    // Network context
    pub network_connection: Option<NetworkContext>,

    // File context
    pub file_path: Option<String>,
    pub file_hash: Option<String>,

    // AI Analysis
    pub ai_analysis: Option<AIAnalysis>,

    // Threat Intelligence
    pub threat_intel: Option<ThreatIntelData>,

    // MITRE ATT&CK mapping
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,

    // Confidence score (0.0 - 1.0)
    pub confidence: f64,

    // Additional metadata
    pub metadata: HashMap<String, String>,

    // Remediation actions
    pub recommended_actions: Vec<String>,

    // Status
    pub status: ThreatStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAnalysis {
    pub explanation: String,
    pub reasoning: Vec<String>,
    pub risk_factors: Vec<String>,
    pub similar_threats: Vec<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelData {
    pub source: String,
    pub reputation_score: f64,
    pub categories: Vec<String>,
    pub last_seen: Option<DateTime<Utc>>,
    pub related_malware: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatStatus {
    Active,
    Investigating,
    Contained,
    Remediated,
    FalsePositive,
    Ignored,
}

/// Behavioral baseline for anomaly detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralBaseline {
    pub process_name: String,
    pub normal_cpu_usage: f64,
    pub normal_memory_usage: u64,
    pub normal_network_activity: u64,
    pub normal_file_operations: u64,
    pub typical_parent_processes: Vec<String>,
    pub typical_child_processes: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub observation_count: u64,
}

/// Configuration for threat detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetectionConfig {
    pub enabled: bool,
    pub behavioral_detection: bool,
    pub signature_detection: bool,
    pub ai_analysis: bool,
    pub threat_intel: bool,
    pub min_severity_to_alert: ThreatSeverity,
    pub auto_remediate: bool,
    pub learning_mode: bool,
    pub scan_interval_ms: u64,
}

impl Default for ThreatDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            behavioral_detection: true,
            signature_detection: true,
            ai_analysis: true,
            threat_intel: false, // Requires API keys
            min_severity_to_alert: ThreatSeverity::Medium,
            auto_remediate: false,
            learning_mode: true,
            scan_interval_ms: 5000,
        }
    }
}
