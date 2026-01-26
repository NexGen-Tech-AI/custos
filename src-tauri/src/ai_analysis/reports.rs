// Security Reports - Generate comprehensive security reports with AI insights

use super::*;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub report_type: ReportType,
    pub executive_summary: String,
    pub posture: Option<SystemSecurityPosture>,
    pub analysis: Option<AnalysisResponse>,
    pub sections: Vec<ReportSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    Daily,
    Weekly,
    Monthly,
    OnDemand,
    Incident,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSection {
    pub title: String,
    pub content: String,
    pub severity: Option<String>,
    pub metrics: Vec<ReportMetric>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetric {
    pub name: String,
    pub value: String,
    pub change: Option<f32>,
    pub trend: Option<String>,
}

impl SecurityReport {
    pub fn new(report_type: ReportType) -> Self {
        Self {
            report_id: uuid::Uuid::new_v4().to_string(),
            generated_at: Utc::now(),
            report_type,
            executive_summary: String::new(),
            posture: None,
            analysis: None,
            sections: Vec::new(),
        }
    }

    pub fn add_section(&mut self, section: ReportSection) {
        self.sections.push(section);
    }

    pub fn to_markdown(&self) -> String {
        let mut md = format!(
            "# Security Report\n\n**Report ID:** {}\n**Generated:** {}\n**Type:** {:?}\n\n",
            self.report_id,
            self.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            self.report_type
        );

        md.push_str("## Executive Summary\n\n");
        md.push_str(&self.executive_summary);
        md.push_str("\n\n");

        if let Some(posture) = &self.posture {
            md.push_str("## Security Posture\n\n");
            md.push_str(&format!("**Overall Score:** {}/100\n\n", posture.overall_score));
            md.push_str(&format!("- Vulnerability Score: {}/100\n", posture.vulnerability_score));
            md.push_str(&format!("- Threat Score: {}/100\n", posture.threat_score));
            md.push_str(&format!("- Configuration Score: {}/100\n", posture.configuration_score));
            md.push_str(&format!("- Compliance Score: {}/100\n\n", posture.compliance_score));
        }

        if let Some(analysis) = &self.analysis {
            md.push_str("## AI Analysis\n\n");
            md.push_str(&format!("**Risk Score:** {}/100\n\n", analysis.risk_score));

            if !analysis.key_findings.is_empty() {
                md.push_str("### Key Findings\n\n");
                for finding in &analysis.key_findings {
                    md.push_str(&format!("- {}\n", finding));
                }
                md.push_str("\n");
            }

            if !analysis.recommendations.is_empty() {
                md.push_str("### Recommendations\n\n");
                for (i, rec) in analysis.recommendations.iter().enumerate() {
                    md.push_str(&format!("{}. **{}** (Impact: {:?}, Effort: {:?})\n", i + 1, rec.title, rec.impact, rec.effort));
                    md.push_str(&format!("   {}\n\n", rec.description));
                }
            }
        }

        for section in &self.sections {
            md.push_str(&format!("## {}\n\n", section.title));
            md.push_str(&section.content);
            md.push_str("\n\n");

            if !section.metrics.is_empty() {
                for metric in &section.metrics {
                    md.push_str(&format!("- **{}:** {}\n", metric.name, metric.value));
                }
                md.push_str("\n");
            }
        }

        md
    }
}
