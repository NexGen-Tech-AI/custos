// AI Analyzer - Uses Claude API to provide intelligent security analysis

use super::*;
use crate::vulnerability::{VulnerabilityFinding, CVESeverity, Misconfiguration};
use crate::threat_detection::ThreatEvent;
use reqwest::Client;
use serde_json::json;

const CLAUDE_API_URL: &str = "https://api.anthropic.com/v1/messages";
const CLAUDE_MODEL: &str = "claude-3-5-sonnet-20241022";

pub struct SecurityAnalyzer {
    api_key: Option<String>,
    client: Client,
}

impl SecurityAnalyzer {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            api_key,
            client: Client::new(),
        }
    }

    /// Analyze vulnerabilities and provide intelligent insights
    pub async fn analyze_vulnerabilities(
        &self,
        vulnerabilities: &[VulnerabilityFinding],
    ) -> Result<AnalysisResponse, String> {
        if self.api_key.is_none() {
            return Err("No API key configured. Please set your Claude API key in Settings.".to_string());
        }

        // Prepare context
        let context = self.prepare_vulnerability_context(vulnerabilities);

        let prompt = format!(
            r#"You are a cybersecurity expert analyzing a system's vulnerability scan results.

VULNERABILITY DATA:
{}

Please analyze these vulnerabilities and provide:
1. A concise executive summary (2-3 sentences)
2. 3-5 key findings that highlight the most important issues
3. Specific, actionable recommendations prioritized by impact and effort
4. Priority actions with clear deadlines
5. An overall risk score (0-100) based on severity, exploitability, and exposure

Format your response as JSON with this structure:
{{
  "summary": "executive summary here",
  "key_findings": ["finding 1", "finding 2", ...],
  "recommendations": [
    {{
      "title": "recommendation title",
      "description": "detailed description",
      "impact": "critical|high|medium|low",
      "effort": "quick|moderate|significant|major",
      "category": "patching|configuration|access_control|monitoring|network_security|application_security|data_protection"
    }}
  ],
  "priority_actions": [
    {{
      "order": 1,
      "action": "specific action to take",
      "reason": "why this is a priority",
      "deadline": "immediate|urgent|soon|planned"
    }}
  ],
  "risk_score": 75
}}

Focus on practical, actionable advice that a system administrator can implement."#,
            context
        );

        self.call_claude_api(&prompt, AnalysisType::VulnerabilitySummary).await
    }

    /// Analyze threat events and provide security assessment
    pub async fn analyze_threats(
        &self,
        threats: &[ThreatEvent],
    ) -> Result<AnalysisResponse, String> {
        if self.api_key.is_none() {
            return Err("No API key configured. Please set your Claude API key in Settings.".to_string());
        }

        let context = self.prepare_threat_context(threats);

        let prompt = format!(
            r#"You are a cybersecurity expert analyzing real-time threat detection events.

THREAT EVENTS:
{}

Analyze these threats and provide:
1. Executive summary of the threat landscape
2. Key findings about active threats and attack patterns
3. Recommendations for threat mitigation and prevention
4. Priority actions to address immediate threats
5. Threat risk score (0-100)

Respond in the same JSON format as before, focusing on immediate security concerns and defensive measures."#,
            context
        );

        self.call_claude_api(&prompt, AnalysisType::ThreatAssessment).await
    }

    /// Generate comprehensive system security posture analysis
    pub async fn analyze_system_posture(
        &self,
        vulnerabilities: &[VulnerabilityFinding],
        threats: &[ThreatEvent],
        misconfigurations: &[Misconfiguration],
    ) -> Result<SystemSecurityPosture, String> {
        if self.api_key.is_none() {
            return Err("No API key configured. Please set your Claude API key in Settings.".to_string());
        }

        let context = format!(
            "VULNERABILITIES:\n{}\n\nTHREATS:\n{}\n\nMISCONFIGURATIONS:\n{}",
            self.prepare_vulnerability_context(vulnerabilities),
            self.prepare_threat_context(threats),
            self.prepare_misconfig_context(misconfigurations)
        );

        let prompt = format!(
            r#"You are a cybersecurity expert providing a comprehensive security posture assessment.

SYSTEM SECURITY DATA:
{}

Provide an overall security posture analysis with:
1. Overall security score (0-100) - higher is better
2. Component scores for vulnerabilities, threats, configuration, and compliance
3. Security trends and trajectory
4. Executive summary

Respond in JSON format:
{{
  "overall_score": 65,
  "vulnerability_score": 60,
  "threat_score": 70,
  "configuration_score": 65,
  "compliance_score": 70,
  "summary": "comprehensive summary here",
  "trends": [
    {{
      "metric": "metric name",
      "direction": "improving|stable|degrading",
      "change_percentage": 5.5,
      "description": "explanation of trend"
    }}
  ]
}}"#,
            context
        );

        self.call_claude_posture_api(&prompt).await
    }

    /// Generate remediation plan for critical issues
    pub async fn generate_remediation_plan(
        &self,
        vulnerabilities: &[VulnerabilityFinding],
        misconfigurations: &[Misconfiguration],
    ) -> Result<AnalysisResponse, String> {
        if self.api_key.is_none() {
            return Err("No API key configured. Please set your Claude API key in Settings.".to_string());
        }

        let context = format!(
            "VULNERABILITIES:\n{}\n\nMISCONFIGURATIONS:\n{}",
            self.prepare_vulnerability_context(vulnerabilities),
            self.prepare_misconfig_context(misconfigurations)
        );

        let prompt = format!(
            r#"You are a cybersecurity expert creating a prioritized remediation plan.

SECURITY ISSUES:
{}

Create a detailed, step-by-step remediation plan that:
1. Prioritizes fixes by risk and impact
2. Groups related fixes for efficiency
3. Provides specific commands or actions where possible
4. Estimates time and effort required
5. Identifies dependencies between fixes

Use the standard JSON response format."#,
            context
        );

        self.call_claude_api(&prompt, AnalysisType::RemediationPlan).await
    }

    // Helper methods

    fn prepare_vulnerability_context(&self, vulnerabilities: &[VulnerabilityFinding]) -> String {
        let critical: Vec<_> = vulnerabilities.iter()
            .filter(|v| v.cve.severity == CVESeverity::Critical)
            .collect();
        let high: Vec<_> = vulnerabilities.iter()
            .filter(|v| v.cve.severity == CVESeverity::High)
            .collect();

        format!(
            "Total vulnerabilities: {}\nCritical: {}\nHigh: {}\n\nTop 10 most severe:\n{}",
            vulnerabilities.len(),
            critical.len(),
            high.len(),
            vulnerabilities.iter()
                .take(10)
                .map(|v| format!(
                    "- {} ({}): {}\n  Package: {} v{}\n  CVSS: {:.1}",
                    v.cve.id,
                    format!("{:?}", v.cve.severity),
                    v.cve.description.lines().next().unwrap_or(""),
                    v.affected_package.name,
                    v.affected_package.version,
                    v.cve.cvss_score.unwrap_or(0.0)
                ))
                .collect::<Vec<_>>()
                .join("\n\n")
        )
    }

    fn prepare_threat_context(&self, threats: &[ThreatEvent]) -> String {
        if threats.is_empty() {
            return "No active threats detected.".to_string();
        }

        format!(
            "Total threat events: {}\n\nRecent threats:\n{}",
            threats.len(),
            threats.iter()
                .take(10)
                .map(|t| format!(
                    "- {}: {}\n  Severity: {:?}\n  Category: {:?}",
                    t.title,
                    t.description.lines().next().unwrap_or(""),
                    t.severity,
                    t.category
                ))
                .collect::<Vec<_>>()
                .join("\n\n")
        )
    }

    fn prepare_misconfig_context(&self, misconfigs: &[Misconfiguration]) -> String {
        if misconfigs.is_empty() {
            return "No misconfigurations detected.".to_string();
        }

        format!(
            "Total misconfigurations: {}\n\nTop issues:\n{}",
            misconfigs.len(),
            misconfigs.iter()
                .take(10)
                .map(|m| format!(
                    "- {}: {}\n  Category: {:?}\n  Remediation: {}",
                    m.title,
                    m.description.lines().next().unwrap_or(""),
                    m.category,
                    m.remediation_steps.first().unwrap_or(&String::from("See details"))
                ))
                .collect::<Vec<_>>()
                .join("\n\n")
        )
    }

    async fn call_claude_api(
        &self,
        prompt: &str,
        analysis_type: AnalysisType,
    ) -> Result<AnalysisResponse, String> {
        let api_key = self.api_key.as_ref().unwrap();

        let request_body = json!({
            "model": CLAUDE_MODEL,
            "max_tokens": 4096,
            "messages": [{
                "role": "user",
                "content": prompt
            }]
        });

        let response = self.client
            .post(CLAUDE_API_URL)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("API error: {}", error_text));
        }

        let response_json: serde_json::Value = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        // Extract text content from Claude's response
        let content = response_json["content"][0]["text"]
            .as_str()
            .ok_or("No content in response")?;

        // Try to find JSON in the response (it might be wrapped in markdown code blocks)
        let json_str = if content.contains("```json") {
            content
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(content)
                .trim()
        } else if content.contains("```") {
            content
                .split("```")
                .nth(1)
                .unwrap_or(content)
                .trim()
        } else {
            content.trim()
        };

        // Parse the analysis from Claude's JSON response
        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse analysis JSON: {}", e))?;

        Ok(AnalysisResponse {
            analysis_type,
            summary: parsed["summary"].as_str().unwrap_or("Analysis complete").to_string(),
            key_findings: parsed["key_findings"]
                .as_array()
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            recommendations: parsed["recommendations"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|r| {
                            Some(Recommendation {
                                title: r["title"].as_str()?.to_string(),
                                description: r["description"].as_str()?.to_string(),
                                impact: match r["impact"].as_str()? {
                                    "critical" => ImpactLevel::Critical,
                                    "high" => ImpactLevel::High,
                                    "medium" => ImpactLevel::Medium,
                                    _ => ImpactLevel::Low,
                                },
                                effort: match r["effort"].as_str()? {
                                    "quick" => EffortLevel::Quick,
                                    "moderate" => EffortLevel::Moderate,
                                    "significant" => EffortLevel::Significant,
                                    _ => EffortLevel::Major,
                                },
                                category: match r["category"].as_str()? {
                                    "patching" => RecommendationCategory::Patching,
                                    "configuration" => RecommendationCategory::Configuration,
                                    "access_control" => RecommendationCategory::AccessControl,
                                    "monitoring" => RecommendationCategory::Monitoring,
                                    "network_security" => RecommendationCategory::NetworkSecurity,
                                    "application_security" => RecommendationCategory::ApplicationSecurity,
                                    _ => RecommendationCategory::DataProtection,
                                },
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            priority_actions: parsed["priority_actions"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|a| {
                            Some(PriorityAction {
                                order: a["order"].as_u64()? as u32,
                                action: a["action"].as_str()?.to_string(),
                                reason: a["reason"].as_str()?.to_string(),
                                deadline: match a["deadline"].as_str()? {
                                    "immediate" => ActionDeadline::Immediate,
                                    "urgent" => ActionDeadline::Urgent,
                                    "soon" => ActionDeadline::Soon,
                                    _ => ActionDeadline::Planned,
                                },
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
            risk_score: parsed["risk_score"].as_u64().unwrap_or(50) as u8,
            confidence: 0.85,
        })
    }

    async fn call_claude_posture_api(&self, prompt: &str) -> Result<SystemSecurityPosture, String> {
        let api_key = self.api_key.as_ref().unwrap();

        let request_body = json!({
            "model": CLAUDE_MODEL,
            "max_tokens": 4096,
            "messages": [{
                "role": "user",
                "content": prompt
            }]
        });

        let response = self.client
            .post(CLAUDE_API_URL)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request_body)
            .send()
            .await
            .map_err(|e| format!("API request failed: {}", e))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("API error: {}", error_text));
        }

        let response_json: serde_json::Value = response.json().await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        let content = response_json["content"][0]["text"]
            .as_str()
            .ok_or("No content in response")?;

        let json_str = if content.contains("```json") {
            content
                .split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(content)
                .trim()
        } else if content.contains("```") {
            content
                .split("```")
                .nth(1)
                .unwrap_or(content)
                .trim()
        } else {
            content.trim()
        };

        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse posture JSON: {}", e))?;

        Ok(SystemSecurityPosture {
            overall_score: parsed["overall_score"].as_u64().unwrap_or(50) as u8,
            vulnerability_score: parsed["vulnerability_score"].as_u64().unwrap_or(50) as u8,
            threat_score: parsed["threat_score"].as_u64().unwrap_or(50) as u8,
            configuration_score: parsed["configuration_score"].as_u64().unwrap_or(50) as u8,
            compliance_score: parsed["compliance_score"].as_u64().unwrap_or(50) as u8,
            summary: parsed["summary"].as_str().unwrap_or("Analysis complete").to_string(),
            trends: parsed["trends"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|t| {
                            Some(SecurityTrend {
                                metric: t["metric"].as_str()?.to_string(),
                                direction: match t["direction"].as_str()? {
                                    "improving" => TrendDirection::Improving,
                                    "degrading" => TrendDirection::Degrading,
                                    _ => TrendDirection::Stable,
                                },
                                change_percentage: t["change_percentage"].as_f64()? as f32,
                                description: t["description"].as_str()?.to_string(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}
