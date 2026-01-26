use super::*;
use regex::Regex;
use std::collections::HashMap;

/// Signature-based detection system
pub struct SignatureDetector {
    process_signatures: Vec<ProcessSignature>,
    file_signatures: Vec<FileSignature>,
    network_signatures: Vec<NetworkSignature>,
    behavior_signatures: Vec<BehaviorSignature>,
}

impl SignatureDetector {
    pub fn new() -> Self {
        Self {
            process_signatures: Self::load_process_signatures(),
            file_signatures: Self::load_file_signatures(),
            network_signatures: Self::load_network_signatures(),
            behavior_signatures: Self::load_behavior_signatures(),
        }
    }

    /// Scan a process against all signatures
    pub fn scan_process(
        &self,
        process_name: &str,
        process_path: &str,
        process_id: u32,
        parent_process: Option<&str>,
        command_line: Option<&str>,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for sig in &self.process_signatures {
            if sig.matches(process_name, process_path, parent_process, command_line) {
                threats.push(ThreatEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    severity: sig.severity.clone(),
                    category: sig.category.clone(),
                    title: format!("{}: {}", sig.name, process_name),
                    description: sig.description.clone(),
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
                    mitre_tactics: sig.mitre_tactics.clone(),
                    mitre_techniques: sig.mitre_techniques.clone(),
                    confidence: sig.confidence,
                    metadata: HashMap::from([
                        ("signature_id".to_string(), sig.id.clone()),
                        ("signature_name".to_string(), sig.name.clone()),
                    ]),
                    recommended_actions: sig.recommended_actions.clone(),
                    status: ThreatStatus::Active,
                });
            }
        }

        threats
    }

    /// Scan file operations
    pub fn scan_file(
        &self,
        file_path: &str,
        file_hash: Option<&str>,
        operation: &str,
        process_name: &str,
        process_id: u32,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for sig in &self.file_signatures {
            if sig.matches(file_path, file_hash, operation) {
                threats.push(ThreatEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    severity: sig.severity.clone(),
                    category: sig.category.clone(),
                    title: format!("{}: {}", sig.name, file_path),
                    description: sig.description.clone(),
                    detection_method: DetectionMethod::Signature,
                    process_id: Some(process_id),
                    process_name: Some(process_name.to_string()),
                    process_path: None,
                    parent_process: None,
                    user: None,
                    network_connection: None,
                    file_path: Some(file_path.to_string()),
                    file_hash: file_hash.map(String::from),
                    ai_analysis: None,
                    threat_intel: None,
                    mitre_tactics: sig.mitre_tactics.clone(),
                    mitre_techniques: sig.mitre_techniques.clone(),
                    confidence: sig.confidence,
                    metadata: HashMap::from([
                        ("signature_id".to_string(), sig.id.clone()),
                        ("operation".to_string(), operation.to_string()),
                    ]),
                    recommended_actions: sig.recommended_actions.clone(),
                    status: ThreatStatus::Active,
                });
            }
        }

        threats
    }

    /// Scan network connections
    pub fn scan_network(
        &self,
        remote_address: &str,
        remote_port: u16,
        protocol: &str,
        process_name: &str,
        process_id: u32,
    ) -> Vec<ThreatEvent> {
        let mut threats = Vec::new();

        for sig in &self.network_signatures {
            if sig.matches(remote_address, remote_port, protocol) {
                threats.push(ThreatEvent {
                    id: uuid::Uuid::new_v4().to_string(),
                    timestamp: chrono::Utc::now(),
                    severity: sig.severity.clone(),
                    category: sig.category.clone(),
                    title: format!("{}: {}:{}", sig.name, remote_address, remote_port),
                    description: sig.description.clone(),
                    detection_method: DetectionMethod::Signature,
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
                    mitre_tactics: sig.mitre_tactics.clone(),
                    mitre_techniques: sig.mitre_techniques.clone(),
                    confidence: sig.confidence,
                    metadata: HashMap::from([
                        ("signature_id".to_string(), sig.id.clone()),
                    ]),
                    recommended_actions: sig.recommended_actions.clone(),
                    status: ThreatStatus::Active,
                });
            }
        }

        threats
    }

    /// Load process signatures (malicious processes, living-off-the-land binaries)
    fn load_process_signatures() -> Vec<ProcessSignature> {
        vec![
            // Credential Dumping Tools
            ProcessSignature {
                id: "PROC_001".to_string(),
                name: "Mimikatz".to_string(),
                description: "Detected Mimikatz credential dumping tool".to_string(),
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::CredentialAccess,
                name_pattern: Some(Regex::new(r"(?i)mimikatz").expect("Invalid Mimikatz regex pattern")),
                path_pattern: None,
                parent_pattern: None,
                cmdline_pattern: None,
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1003".to_string()],
                confidence: 0.99,
                recommended_actions: vec![
                    "Immediately terminate process".to_string(),
                    "Isolate system from network".to_string(),
                    "Force password reset for all users".to_string(),
                    "Review authentication logs".to_string(),
                ],
            },
            ProcessSignature {
                id: "PROC_002".to_string(),
                name: "PsExec".to_string(),
                description: "Detected PsExec remote execution tool".to_string(),
                severity: ThreatSeverity::High,
                category: ThreatCategory::LateralMovement,
                name_pattern: Some(Regex::new(r"(?i)psexe[cs]?\.exe").expect("Invalid PsExec regex pattern")),
                path_pattern: None,
                parent_pattern: None,
                cmdline_pattern: None,
                mitre_tactics: vec!["Lateral Movement".to_string(), "Execution".to_string()],
                mitre_techniques: vec!["T1570".to_string(), "T1569".to_string()],
                confidence: 0.85,
                recommended_actions: vec![
                    "Investigate remote connections".to_string(),
                    "Review command line arguments".to_string(),
                    "Check for unauthorized access".to_string(),
                ],
            },
            // Reverse Shells & C2
            ProcessSignature {
                id: "PROC_003".to_string(),
                name: "PowerShell Encoded Command".to_string(),
                description: "PowerShell executing encoded/obfuscated command".to_string(),
                severity: ThreatSeverity::High,
                category: ThreatCategory::Execution,
                name_pattern: Some(Regex::new(r"(?i)powershell").expect("Invalid PowerShell regex pattern")),
                path_pattern: None,
                parent_pattern: None,
                cmdline_pattern: Some(Regex::new(r"(?i)(-enc|-e\s|encodedcommand)").expect("Invalid PowerShell encoded command regex pattern")),
                mitre_tactics: vec!["Execution".to_string(), "Defense Evasion".to_string()],
                mitre_techniques: vec!["T1059.001".to_string(), "T1027".to_string()],
                confidence: 0.90,
                recommended_actions: vec![
                    "Decode and analyze command".to_string(),
                    "Check process tree for suspicious parents".to_string(),
                    "Review network connections".to_string(),
                ],
            },
            // Living Off The Land
            ProcessSignature {
                id: "PROC_004".to_string(),
                name: "Suspicious WMI Execution".to_string(),
                description: "WMI used for lateral movement or execution".to_string(),
                severity: ThreatSeverity::Medium,
                category: ThreatCategory::Execution,
                name_pattern: Some(Regex::new(r"(?i)wmic\.exe").expect("Invalid WMIC regex pattern")),
                path_pattern: None,
                parent_pattern: Some(Regex::new(r"(?i)(cmd\.exe|powershell\.exe)").expect("Invalid WMIC parent regex pattern")),
                cmdline_pattern: Some(Regex::new(r"(?i)(process\s+call\s+create|/node:)").expect("Invalid WMIC cmdline regex pattern")),
                mitre_tactics: vec!["Execution".to_string()],
                mitre_techniques: vec!["T1047".to_string()],
                confidence: 0.75,
                recommended_actions: vec![
                    "Investigate WMI query".to_string(),
                    "Check for remote execution".to_string(),
                ],
            },
            // Persistence Mechanisms
            ProcessSignature {
                id: "PROC_005".to_string(),
                name: "Suspicious Scheduled Task".to_string(),
                description: "Scheduled task creation for persistence".to_string(),
                severity: ThreatSeverity::Medium,
                category: ThreatCategory::Persistence,
                name_pattern: Some(Regex::new(r"(?i)schtasks\.exe").expect("Invalid schtasks regex pattern")),
                path_pattern: None,
                parent_pattern: None,
                cmdline_pattern: Some(Regex::new(r"(?i)/create").expect("Invalid schtasks cmdline regex pattern")),
                mitre_tactics: vec!["Persistence".to_string(), "Execution".to_string()],
                mitre_techniques: vec!["T1053.005".to_string()],
                confidence: 0.70,
                recommended_actions: vec![
                    "Review scheduled task details".to_string(),
                    "Verify task legitimacy".to_string(),
                ],
            },
            // Ransomware Indicators
            ProcessSignature {
                id: "PROC_006".to_string(),
                name: "Known Ransomware Process".to_string(),
                description: "Process matches known ransomware signature".to_string(),
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::Ransomware,
                name_pattern: Some(Regex::new(r"(?i)(wannacry|ryuk|lockbit|blackcat|conti|revil)").expect("Invalid ransomware name regex pattern")),
                path_pattern: None,
                parent_pattern: None,
                cmdline_pattern: None,
                mitre_tactics: vec!["Impact".to_string()],
                mitre_techniques: vec!["T1486".to_string()],
                confidence: 0.95,
                recommended_actions: vec![
                    "IMMEDIATELY KILL PROCESS".to_string(),
                    "Isolate system from network".to_string(),
                    "Disable network shares".to_string(),
                    "Contact incident response team".to_string(),
                    "Prepare for recovery from backups".to_string(),
                ],
            },
        ]
    }

    /// Load file operation signatures
    fn load_file_signatures() -> Vec<FileSignature> {
        vec![
            FileSignature {
                id: "FILE_001".to_string(),
                name: "SAM Database Access".to_string(),
                description: "Unauthorized access to Windows SAM database".to_string(),
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::CredentialAccess,
                path_pattern: Some(Regex::new(r"(?i)Windows\\System32\\config\\SAM").expect("Invalid SAM path regex pattern")),
                hash_list: vec![],
                operation_pattern: Some(Regex::new(r"(?i)(read|copy)").expect("Invalid SAM operation regex pattern")),
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1003.002".to_string()],
                confidence: 0.95,
                recommended_actions: vec![
                    "Terminate accessing process".to_string(),
                    "Force password reset".to_string(),
                    "Review authentication logs".to_string(),
                ],
            },
            FileSignature {
                id: "FILE_002".to_string(),
                name: "LSASS Memory Dump".to_string(),
                description: "LSASS process memory being dumped".to_string(),
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::CredentialAccess,
                path_pattern: Some(Regex::new(r"(?i)lsass.*\.dmp").expect("Invalid LSASS dump path regex pattern")),
                hash_list: vec![],
                operation_pattern: Some(Regex::new(r"(?i)(create|write)").expect("Invalid LSASS dump operation regex pattern")),
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1003.001".to_string()],
                confidence: 0.98,
                recommended_actions: vec![
                    "Immediately terminate dumping process".to_string(),
                    "Delete dump file".to_string(),
                    "Reset credentials".to_string(),
                ],
            },
            FileSignature {
                id: "FILE_003".to_string(),
                name: "Ransomware Note Creation".to_string(),
                description: "Ransomware ransom note file detected".to_string(),
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::Ransomware,
                path_pattern: Some(Regex::new(r"(?i)(README.*\.txt|DECRYPT.*\.txt|RESTORE.*\.txt|.*RANSOM.*\.txt)").expect("Invalid ransomware note path regex pattern")),
                hash_list: vec![],
                operation_pattern: Some(Regex::new(r"(?i)create").expect("Invalid ransomware note operation regex pattern")),
                mitre_tactics: vec!["Impact".to_string()],
                mitre_techniques: vec!["T1486".to_string()],
                confidence: 0.99,
                recommended_actions: vec![
                    "IMMEDIATELY ISOLATE SYSTEM".to_string(),
                    "Kill all encryption processes".to_string(),
                    "Disable network shares".to_string(),
                    "Initiate incident response".to_string(),
                ],
            },
            FileSignature {
                id: "FILE_004".to_string(),
                name: "Browser Credential Theft".to_string(),
                description: "Access to browser stored credentials".to_string(),
                severity: ThreatSeverity::High,
                category: ThreatCategory::CredentialAccess,
                path_pattern: Some(Regex::new(r"(?i)(Chrome|Firefox|Edge).*Login Data").expect("Invalid browser credentials path regex pattern")),
                hash_list: vec![],
                operation_pattern: Some(Regex::new(r"(?i)(read|copy)").expect("Invalid browser credentials operation regex pattern")),
                mitre_tactics: vec!["Credential Access".to_string()],
                mitre_techniques: vec!["T1555.003".to_string()],
                confidence: 0.80,
                recommended_actions: vec![
                    "Investigate accessing process".to_string(),
                    "Change saved passwords".to_string(),
                ],
            },
        ]
    }

    /// Load network signatures (C2 servers, malicious IPs, suspicious patterns)
    fn load_network_signatures() -> Vec<NetworkSignature> {
        vec![
            NetworkSignature {
                id: "NET_001".to_string(),
                name: "Tor Network Connection".to_string(),
                description: "Connection to Tor network detected".to_string(),
                severity: ThreatSeverity::Medium,
                category: ThreatCategory::CommandAndControl,
                ip_pattern: None,
                port_list: vec![9001, 9030, 9050, 9051],
                protocol_pattern: None,
                mitre_tactics: vec!["Command and Control".to_string()],
                mitre_techniques: vec!["T1090".to_string()],
                confidence: 0.75,
                recommended_actions: vec![
                    "Investigate process using Tor".to_string(),
                    "Review network policy".to_string(),
                ],
            },
            NetworkSignature {
                id: "NET_002".to_string(),
                name: "Known C2 Port".to_string(),
                description: "Connection to common C2 server port".to_string(),
                severity: ThreatSeverity::High,
                category: ThreatCategory::CommandAndControl,
                ip_pattern: None,
                port_list: vec![4444, 5555, 6666, 8888, 31337],
                protocol_pattern: Some(Regex::new(r"(?i)tcp").expect("Invalid TCP protocol regex pattern")),
                mitre_tactics: vec!["Command and Control".to_string()],
                mitre_techniques: vec!["T1071".to_string()],
                confidence: 0.70,
                recommended_actions: vec![
                    "Investigate remote endpoint".to_string(),
                    "Analyze network traffic".to_string(),
                    "Check for reverse shell".to_string(),
                ],
            },
            NetworkSignature {
                id: "NET_003".to_string(),
                name: "Cryptocurrency Mining Pool".to_string(),
                description: "Connection to known mining pool".to_string(),
                severity: ThreatSeverity::High,
                category: ThreatCategory::Impact,
                ip_pattern: Some(Regex::new(r"pool\..*|.*\.pool\.").expect("Invalid mining pool IP regex pattern")),
                port_list: vec![3333, 4444, 5555],
                protocol_pattern: None,
                mitre_tactics: vec!["Impact".to_string()],
                mitre_techniques: vec!["T1496".to_string()],
                confidence: 0.85,
                recommended_actions: vec![
                    "Terminate mining process".to_string(),
                    "Remove cryptominer".to_string(),
                ],
            },
        ]
    }

    /// Load behavioral signatures (sequences of actions that indicate threats)
    fn load_behavior_signatures() -> Vec<BehaviorSignature> {
        vec![
            BehaviorSignature {
                id: "BEH_001".to_string(),
                name: "Rapid File Encryption Pattern".to_string(),
                description: "Multiple files being encrypted in rapid succession".to_string(),
                severity: ThreatSeverity::Critical,
                category: ThreatCategory::Ransomware,
                mitre_tactics: vec!["Impact".to_string()],
                mitre_techniques: vec!["T1486".to_string()],
                confidence: 0.95,
                recommended_actions: vec![
                    "IMMEDIATELY KILL PROCESS".to_string(),
                    "Isolate system".to_string(),
                ],
            },
        ]
    }
}

/// Process signature
#[derive(Debug, Clone)]
struct ProcessSignature {
    id: String,
    name: String,
    description: String,
    severity: ThreatSeverity,
    category: ThreatCategory,
    name_pattern: Option<Regex>,
    path_pattern: Option<Regex>,
    parent_pattern: Option<Regex>,
    cmdline_pattern: Option<Regex>,
    mitre_tactics: Vec<String>,
    mitre_techniques: Vec<String>,
    confidence: f64,
    recommended_actions: Vec<String>,
}

impl ProcessSignature {
    fn matches(
        &self,
        process_name: &str,
        process_path: &str,
        parent_process: Option<&str>,
        command_line: Option<&str>,
    ) -> bool {
        let name_match = self.name_pattern.as_ref()
            .map(|p| p.is_match(process_name))
            .unwrap_or(true);

        let path_match = self.path_pattern.as_ref()
            .map(|p| p.is_match(process_path))
            .unwrap_or(true);

        let parent_match = self.parent_pattern.as_ref()
            .map(|p| parent_process.map(|pp| p.is_match(pp)).unwrap_or(false))
            .unwrap_or(true);

        let cmdline_match = self.cmdline_pattern.as_ref()
            .map(|p| command_line.map(|c| p.is_match(c)).unwrap_or(false))
            .unwrap_or(true);

        name_match && path_match && parent_match && cmdline_match
    }
}

/// File operation signature
#[derive(Debug, Clone)]
struct FileSignature {
    id: String,
    name: String,
    description: String,
    severity: ThreatSeverity,
    category: ThreatCategory,
    path_pattern: Option<Regex>,
    hash_list: Vec<String>,
    operation_pattern: Option<Regex>,
    mitre_tactics: Vec<String>,
    mitre_techniques: Vec<String>,
    confidence: f64,
    recommended_actions: Vec<String>,
}

impl FileSignature {
    fn matches(&self, file_path: &str, file_hash: Option<&str>, operation: &str) -> bool {
        let path_match = self.path_pattern.as_ref()
            .map(|p| p.is_match(file_path))
            .unwrap_or(true);

        let hash_match = if !self.hash_list.is_empty() {
            file_hash.map(|h| self.hash_list.contains(&h.to_string())).unwrap_or(false)
        } else {
            true
        };

        let op_match = self.operation_pattern.as_ref()
            .map(|p| p.is_match(operation))
            .unwrap_or(true);

        path_match && hash_match && op_match
    }
}

/// Network connection signature
#[derive(Debug, Clone)]
struct NetworkSignature {
    id: String,
    name: String,
    description: String,
    severity: ThreatSeverity,
    category: ThreatCategory,
    ip_pattern: Option<Regex>,
    port_list: Vec<u16>,
    protocol_pattern: Option<Regex>,
    mitre_tactics: Vec<String>,
    mitre_techniques: Vec<String>,
    confidence: f64,
    recommended_actions: Vec<String>,
}

impl NetworkSignature {
    fn matches(&self, remote_address: &str, remote_port: u16, protocol: &str) -> bool {
        let ip_match = self.ip_pattern.as_ref()
            .map(|p| p.is_match(remote_address))
            .unwrap_or(true);

        let port_match = if !self.port_list.is_empty() {
            self.port_list.contains(&remote_port)
        } else {
            true
        };

        let protocol_match = self.protocol_pattern.as_ref()
            .map(|p| p.is_match(protocol))
            .unwrap_or(true);

        ip_match && port_match && protocol_match
    }
}

/// Behavioral pattern signature
#[derive(Debug, Clone)]
struct BehaviorSignature {
    id: String,
    name: String,
    description: String,
    severity: ThreatSeverity,
    category: ThreatCategory,
    mitre_tactics: Vec<String>,
    mitre_techniques: Vec<String>,
    confidence: f64,
    recommended_actions: Vec<String>,
}
