// AI Analysis Module - Intelligent security analysis using Claude AI
// Analyzes vulnerabilities, threats, and system configuration to provide actionable insights

pub mod analyzer;
pub mod reports;
pub mod report_generator;
pub mod report_export;

pub use analyzer::*;
pub use reports::*;
pub use report_generator::*;
pub use report_export::*;

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRequest {
    pub analysis_type: AnalysisType,
    pub context: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisType {
    VulnerabilitySummary,
    ThreatAssessment,
    SystemPosture,
    RemediationPlan,
    SecurityTrends,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResponse {
    pub analysis_type: AnalysisType,
    pub summary: String,
    pub key_findings: Vec<String>,
    pub recommendations: Vec<Recommendation>,
    pub priority_actions: Vec<PriorityAction>,
    pub risk_score: u8, // 0-100
    pub confidence: f32, // 0.0-1.0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    pub title: String,
    pub description: String,
    pub impact: ImpactLevel,
    pub effort: EffortLevel,
    pub category: RecommendationCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffortLevel {
    Quick,      // < 1 hour
    Moderate,   // 1-8 hours
    Significant, // 1-3 days
    Major,      // > 3 days
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationCategory {
    Patching,
    Configuration,
    AccessControl,
    Monitoring,
    NetworkSecurity,
    ApplicationSecurity,
    DataProtection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityAction {
    pub order: u32,
    pub action: String,
    pub reason: String,
    pub deadline: ActionDeadline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionDeadline {
    Immediate,  // Within 24 hours
    Urgent,     // Within 1 week
    Soon,       // Within 1 month
    Planned,    // Within 3 months
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSecurityPosture {
    pub overall_score: u8,
    pub vulnerability_score: u8,
    pub threat_score: u8,
    pub configuration_score: u8,
    pub compliance_score: u8,
    pub trends: Vec<SecurityTrend>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTrend {
    pub metric: String,
    pub direction: TrendDirection,
    pub change_percentage: f32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendDirection {
    Improving,
    Stable,
    Degrading,
}
