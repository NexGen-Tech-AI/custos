use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AI-powered threat analyzer using Claude API
pub struct AIAnalyzer {
    api_key: Option<String>,
    enabled: bool,
    client: reqwest::Client,
}

impl AIAnalyzer {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            enabled: api_key.is_some(),
            api_key,
            client: reqwest::Client::new(),
        }
    }

    /// Analyze a threat event with AI
    pub async fn analyze_threat(&self, event: &ThreatEvent) -> Option<AIAnalysis> {
        if !self.enabled {
            return None;
        }

        let prompt = self.build_analysis_prompt(event);

        match self.call_claude_api(&prompt).await {
            Ok(response) => Some(self.parse_analysis_response(&response)),
            Err(e) => {
                eprintln!("AI analysis failed: {}", e);
                None
            }
        }
    }

    /// Analyze a process for potential threats
    pub async fn analyze_process(
        &self,
        process_name: &str,
        process_path: &str,
        parent_process: Option<&str>,
        command_line: Option<&str>,
        network_connections: &[String],
        file_operations: &[String],
    ) -> Option<AIAnalysis> {
        if !self.enabled {
            return None;
        }

        let prompt = format!(
            r#"Analyze this system process for security threats:

Process Name: {}
Process Path: {}
Parent Process: {}
Command Line: {}
Network Connections: {}
Recent File Operations: {}

Provide a security analysis covering:
1. Is this process legitimate or potentially malicious?
2. What are the key risk factors?
3. What similar threats does this resemble?
4. What actions should be taken?

Format your response as:
EXPLANATION: [Brief explanation]
REASONING: [Bullet points of reasoning]
RISK_FACTORS: [Bullet points of risk factors]
SIMILAR_THREATS: [List of similar threat types]
CONFIDENCE: [0.0-1.0]"#,
            process_name,
            process_path,
            parent_process.unwrap_or("N/A"),
            command_line.unwrap_or("N/A"),
            network_connections.join(", "),
            file_operations.join(", ")
        );

        match self.call_claude_api(&prompt).await {
            Ok(response) => Some(self.parse_analysis_response(&response)),
            Err(e) => {
                eprintln!("AI process analysis failed: {}", e);
                None
            }
        }
    }

    /// Get remediation recommendations
    pub async fn get_remediation_steps(&self, event: &ThreatEvent) -> Vec<String> {
        if !self.enabled {
            return event.recommended_actions.clone();
        }

        let prompt = format!(
            r#"Provide detailed remediation steps for this security threat:

Threat: {}
Description: {}
Severity: {:?}
Category: {:?}
MITRE Tactics: {}
MITRE Techniques: {}

Provide step-by-step remediation actions in priority order.
Format as numbered list."#,
            event.title,
            event.description,
            event.severity,
            event.category,
            event.mitre_tactics.join(", "),
            event.mitre_techniques.join(", ")
        );

        match self.call_claude_api(&prompt).await {
            Ok(response) => self.parse_remediation_steps(&response),
            Err(_) => event.recommended_actions.clone(),
        }
    }

    /// Explain a threat in simple terms
    pub async fn explain_threat(&self, event: &ThreatEvent) -> String {
        if !self.enabled {
            return event.description.clone();
        }

        let prompt = format!(
            r#"Explain this cybersecurity threat in simple, non-technical terms:

Threat: {}
Technical Description: {}
Severity: {:?}

Provide a clear explanation that a non-technical user can understand."#,
            event.title,
            event.description,
            event.severity
        );

        match self.call_claude_api(&prompt).await {
            Ok(response) => response,
            Err(_) => event.description.clone(),
        }
    }

    /// Call Claude API
    async fn call_claude_api(&self, prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
        let api_key = self.api_key.as_ref()
            .ok_or("API key not configured")?;

        let request_body = ClaudeRequest {
            model: "claude-3-5-sonnet-20241022".to_string(),
            max_tokens: 1024,
            messages: vec![
                Message {
                    role: "user".to_string(),
                    content: prompt.to_string(),
                }
            ],
        };

        let response = self.client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("API error: {}", error_text).into());
        }

        let claude_response: ClaudeResponse = response.json().await?;

        Ok(claude_response.content
            .first()
            .map(|c| c.text.clone())
            .unwrap_or_default())
    }

    /// Build analysis prompt for a threat event
    fn build_analysis_prompt(&self, event: &ThreatEvent) -> String {
        format!(
            r#"Analyze this security threat detection:

Threat: {}
Description: {}
Severity: {:?}
Category: {:?}
Detection Method: {:?}
Process: {}
Process Path: {}
Parent Process: {}
MITRE Tactics: {}
MITRE Techniques: {}
Confidence: {}

Provide a detailed security analysis covering:
1. Is this a true threat or potential false positive?
2. What are the key risk factors?
3. What similar threats does this resemble?
4. What immediate actions should be taken?

Format your response as:
EXPLANATION: [Brief explanation]
REASONING: [Bullet points of reasoning]
RISK_FACTORS: [Bullet points of risk factors]
SIMILAR_THREATS: [List of similar threat types]
CONFIDENCE: [0.0-1.0]"#,
            event.title,
            event.description,
            event.severity,
            event.category,
            event.detection_method,
            event.process_name.as_ref().unwrap_or(&"N/A".to_string()),
            event.process_path.as_ref().unwrap_or(&"N/A".to_string()),
            event.parent_process.as_ref().unwrap_or(&"N/A".to_string()),
            event.mitre_tactics.join(", "),
            event.mitre_techniques.join(", "),
            event.confidence
        )
    }

    /// Parse AI analysis response
    fn parse_analysis_response(&self, response: &str) -> AIAnalysis {
        let mut explanation = String::new();
        let mut reasoning = Vec::new();
        let mut risk_factors = Vec::new();
        let mut similar_threats = Vec::new();
        let mut confidence = 0.5;

        let mut current_section = "";

        for line in response.lines() {
            let line = line.trim();

            if line.starts_with("EXPLANATION:") {
                current_section = "explanation";
                explanation = line.trim_start_matches("EXPLANATION:").trim().to_string();
            } else if line.starts_with("REASONING:") {
                current_section = "reasoning";
            } else if line.starts_with("RISK_FACTORS:") {
                current_section = "risk_factors";
            } else if line.starts_with("SIMILAR_THREATS:") {
                current_section = "similar_threats";
            } else if line.starts_with("CONFIDENCE:") {
                if let Ok(conf) = line.trim_start_matches("CONFIDENCE:").trim().parse::<f64>() {
                    confidence = conf;
                }
            } else if !line.is_empty() {
                match current_section {
                    "explanation" => {
                        if !explanation.is_empty() {
                            explanation.push(' ');
                        }
                        explanation.push_str(line);
                    }
                    "reasoning" => {
                        if line.starts_with('-') || line.starts_with('•') {
                            reasoning.push(line.trim_start_matches('-').trim_start_matches('•').trim().to_string());
                        }
                    }
                    "risk_factors" => {
                        if line.starts_with('-') || line.starts_with('•') {
                            risk_factors.push(line.trim_start_matches('-').trim_start_matches('•').trim().to_string());
                        }
                    }
                    "similar_threats" => {
                        if line.starts_with('-') || line.starts_with('•') {
                            similar_threats.push(line.trim_start_matches('-').trim_start_matches('•').trim().to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        AIAnalysis {
            explanation,
            reasoning,
            risk_factors,
            similar_threats,
            confidence,
        }
    }

    /// Parse remediation steps from response
    fn parse_remediation_steps(&self, response: &str) -> Vec<String> {
        response
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }

                // Remove numbering like "1. ", "2. ", etc.
                let cleaned = line
                    .trim_start_matches(char::is_numeric)
                    .trim_start_matches('.')
                    .trim_start_matches('-')
                    .trim_start_matches('•')
                    .trim();

                if cleaned.is_empty() {
                    None
                } else {
                    Some(cleaned.to_string())
                }
            })
            .collect()
    }
}

#[derive(Debug, Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<Message>,
}

#[derive(Debug, Serialize)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ClaudeResponse {
    content: Vec<ContentBlock>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

/// Heuristic analyzer for unknown threats
pub struct HeuristicAnalyzer {
    suspicion_threshold: f64,
}

impl HeuristicAnalyzer {
    pub fn new(suspicion_threshold: f64) -> Self {
        Self {
            suspicion_threshold: suspicion_threshold.clamp(0.0, 1.0),
        }
    }

    /// Analyze process behavior using heuristics
    pub fn analyze_process(
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
        let mut threats = Vec::new();
        let mut suspicion_score = 0.0;
        let mut indicators = Vec::new();

        // Check for suspicious characteristics

        // 1. Unusual process location
        if !self.is_standard_location(process_path) {
            suspicion_score += 0.15;
            indicators.push("Process running from non-standard location".to_string());
        }

        // 2. Suspicious parent process
        if let Some(parent) = parent_process {
            if self.is_suspicious_parent(parent, process_name) {
                suspicion_score += 0.20;
                indicators.push(format!("Unusual parent process: {}", parent));
            }
        }

        // 3. Obfuscated or suspicious command line
        if let Some(cmdline) = command_line {
            if self.is_obfuscated(cmdline) {
                suspicion_score += 0.25;
                indicators.push("Obfuscated command line detected".to_string());
            }
        }

        // 4. Excessive resource usage
        if cpu_usage > 80.0 && memory_usage > 1_000_000_000 {
            suspicion_score += 0.15;
            indicators.push("Excessive resource consumption".to_string());
        }

        // 5. High network activity
        if network_connections > 10 {
            suspicion_score += 0.10;
            indicators.push(format!("High network activity: {} connections", network_connections));
        }

        // 6. Rapid file operations
        if file_operations > 100 {
            suspicion_score += 0.15;
            indicators.push(format!("Rapid file operations: {}", file_operations));
        }

        // Create threat event if above threshold
        if suspicion_score >= self.suspicion_threshold {
            threats.push(ThreatEvent {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                severity: self.score_to_severity(suspicion_score),
                category: ThreatCategory::Unknown,
                title: format!("Suspicious Process Behavior: {}", process_name),
                description: format!(
                    "Process exhibits multiple suspicious characteristics. Suspicion score: {:.1}%",
                    suspicion_score * 100.0
                ),
                detection_method: DetectionMethod::Heuristic,
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
                mitre_tactics: vec!["Unknown".to_string()],
                mitre_techniques: vec![],
                confidence: suspicion_score,
                metadata: HashMap::from([
                    ("suspicion_score".to_string(), format!("{:.2}", suspicion_score)),
                    ("indicators".to_string(), indicators.join("; ")),
                ]),
                recommended_actions: vec![
                    "Investigate process origin and purpose".to_string(),
                    "Review process behavior and network activity".to_string(),
                    "Consider isolating process for analysis".to_string(),
                ],
                status: ThreatStatus::Active,
            });
        }

        threats
    }

    fn is_standard_location(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();

        // Windows standard locations
        if path_lower.contains("windows\\system32") ||
           path_lower.contains("windows\\syswow64") ||
           path_lower.contains("program files") ||
           path_lower.contains("programdata") {
            return true;
        }

        // Linux standard locations
        if path_lower.starts_with("/usr/") ||
           path_lower.starts_with("/bin/") ||
           path_lower.starts_with("/sbin/") {
            return true;
        }

        false
    }

    fn is_suspicious_parent(&self, parent: &str, process: &str) -> bool {
        let parent_lower = parent.to_lowercase();

        // Suspicious: Office apps spawning shells
        if (parent_lower.contains("winword") ||
            parent_lower.contains("excel") ||
            parent_lower.contains("powerpnt")) &&
           (process.to_lowercase().contains("cmd") ||
            process.to_lowercase().contains("powershell")) {
            return true;
        }

        // Suspicious: Browser spawning system utilities
        if (parent_lower.contains("chrome") ||
            parent_lower.contains("firefox") ||
            parent_lower.contains("edge")) &&
           (process.to_lowercase().contains("cmd") ||
            process.to_lowercase().contains("wmic")) {
            return true;
        }

        false
    }

    fn is_obfuscated(&self, cmdline: &str) -> bool {
        let indicators = [
            "frombase64",
            "encodedcommand",
            "-enc",
            "invoke-expression",
            "iex",
            "downloadstring",
            "invoke-webrequest",
            "curl.*|.*powershell",
        ];

        let cmdline_lower = cmdline.to_lowercase();
        indicators.iter().any(|&i| cmdline_lower.contains(i))
    }

    fn score_to_severity(&self, score: f64) -> ThreatSeverity {
        if score >= 0.9 {
            ThreatSeverity::Critical
        } else if score >= 0.7 {
            ThreatSeverity::High
        } else if score >= 0.5 {
            ThreatSeverity::Medium
        } else if score >= 0.3 {
            ThreatSeverity::Low
        } else {
            ThreatSeverity::Info
        }
    }
}
