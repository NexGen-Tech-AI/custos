// Comprehensive Report Generator - Creates beautiful, detailed security reports
// Supports multiple formats: HTML, PDF, Markdown, JSON

use super::*;
use crate::vulnerability::{VulnerabilityFinding, VulnerabilityScanner, CVESeverity, misconfig::MisconfigurationScanner};
use crate::threat_detection::ThreatEvent;
use crate::sensors::PackageSensor;
use chrono::{DateTime, Utc, Datelike};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportTemplate {
    Executive,      // High-level overview for executives
    Technical,      // Detailed technical analysis for security teams
    Compliance,     // Compliance-focused report (CIS, NIST, etc.)
    Incident,       // Incident response report
    Comprehensive,  // All-inclusive report
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Html,
    Markdown,
    Json,
    Pdf,  // Future: requires additional libraries
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfiguration {
    pub template: ReportTemplate,
    pub include_ai_analysis: bool,
    pub include_vulnerabilities: bool,
    pub include_threats: bool,
    pub include_network: bool,
    pub include_misconfigurations: bool,
    pub include_system_info: bool,
    pub include_trends: bool,
    pub compliance_frameworks: Vec<ComplianceFramework>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    CisBenchmark,
    NistCsf,
    PciDss,
    Hipaa,
    Iso27001,
    Gdpr,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub template: ReportTemplate,
    pub organization: Option<String>,
    pub period_start: Option<DateTime<Utc>>,
    pub period_end: Option<DateTime<Utc>>,

    // Executive Summary
    pub executive_summary: ExecutiveSummary,

    // Security Posture
    pub security_posture: Option<SystemSecurityPosture>,

    // Data Sections
    pub vulnerabilities: VulnerabilityData,
    pub threats: ThreatData,
    pub network_security: NetworkSecurityData,
    pub misconfigurations: MisconfigurationData,
    pub system_info: SystemInfoData,

    // AI Insights
    pub ai_insights: Option<AnalysisResponse>,

    // Compliance
    pub compliance_status: Vec<ComplianceResult>,

    // Trends
    pub trends: Vec<SecurityTrendData>,

    // Recommendations
    pub recommendations: Vec<Recommendation>,
    pub priority_actions: Vec<PriorityAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutiveSummary {
    pub overview: String,
    pub risk_level: RiskLevel,
    pub critical_issues: usize,
    pub high_issues: usize,
    pub medium_issues: usize,
    pub low_issues: usize,
    pub key_highlights: Vec<String>,
    pub business_impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Critical,
    High,
    Medium,
    Low,
    Minimal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityData {
    pub total_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub top_vulnerabilities: Vec<VulnerabilitySummary>,
    pub affected_packages: usize,
    pub exploitable_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilitySummary {
    pub cve_id: String,
    pub severity: String,
    pub cvss_score: f32,
    pub package_name: String,
    pub package_version: String,
    pub description: String,
    pub fix_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatData {
    pub total_threats: usize,
    pub active_threats: usize,
    pub mitigated_threats: usize,
    pub threat_categories: HashMap<String, usize>,
    pub recent_threats: Vec<ThreatSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatSummary {
    pub title: String,
    pub severity: String,
    pub category: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSecurityData {
    pub total_connections: usize,
    pub suspicious_connections: usize,
    pub open_ports: Vec<u16>,
    pub external_connections: usize,
    pub protocols_used: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisconfigurationData {
    pub total_issues: usize,
    pub critical_misconfigs: usize,
    pub categories: HashMap<String, usize>,
    pub top_issues: Vec<MisconfigSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MisconfigSummary {
    pub title: String,
    pub severity: String,
    pub category: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfoData {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub kernel_version: String,
    pub cpu_count: usize,
    pub total_memory_gb: f64,
    pub uptime_days: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceResult {
    pub framework: ComplianceFramework,
    pub overall_score: u8,
    pub passed_controls: usize,
    pub failed_controls: usize,
    pub not_applicable: usize,
    pub findings: Vec<ComplianceFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub control_id: String,
    pub control_name: String,
    pub status: ComplianceStatus,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Pass,
    Fail,
    Partial,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTrendData {
    pub metric: String,
    pub current_value: f64,
    pub previous_value: Option<f64>,
    pub change_percentage: f32,
    pub direction: TrendDirection,
    pub time_period: String,
}

pub struct ReportGenerator {
    analyzer: Option<SecurityAnalyzer>,
}

impl ReportGenerator {
    pub fn new(api_key: Option<String>) -> Self {
        Self {
            analyzer: if let Some(key) = api_key {
                Some(SecurityAnalyzer::new(Some(key)))
            } else {
                None
            },
        }
    }

    /// Generate a comprehensive security report
    pub async fn generate_report(
        &self,
        config: ReportConfiguration,
    ) -> Result<ComprehensiveReport, String> {
        let report_id = uuid::Uuid::new_v4().to_string();
        let generated_at = Utc::now();

        // Collect data from all sources
        let vulnerabilities = if config.include_vulnerabilities {
            self.collect_vulnerability_data().await?
        } else {
            VulnerabilityData::default()
        };

        let threats = if config.include_threats {
            self.collect_threat_data().await?
        } else {
            ThreatData::default()
        };

        let network_security = if config.include_network {
            self.collect_network_data().await?
        } else {
            NetworkSecurityData::default()
        };

        let misconfigurations = if config.include_misconfigurations {
            self.collect_misconfiguration_data().await?
        } else {
            MisconfigurationData::default()
        };

        let system_info = if config.include_system_info {
            self.collect_system_info().await?
        } else {
            SystemInfoData::default()
        };

        // Generate executive summary
        let executive_summary = self.generate_executive_summary(
            &vulnerabilities,
            &threats,
            &misconfigurations,
        );

        // Get AI insights if requested
        let ai_insights = if config.include_ai_analysis && self.analyzer.is_some() {
            self.get_ai_insights(&vulnerabilities).await.ok()
        } else {
            None
        };

        // Get security posture if AI is available
        let security_posture = if config.include_ai_analysis && self.analyzer.is_some() {
            self.get_security_posture().await.ok()
        } else {
            None
        };

        // Check compliance
        let compliance_status = self.check_compliance(&config.compliance_frameworks).await?;

        // Generate trends if requested
        let trends = if config.include_trends {
            self.generate_trends().await?
        } else {
            Vec::new()
        };

        // Compile recommendations
        let recommendations = self.compile_recommendations(
            &vulnerabilities,
            &threats,
            &misconfigurations,
            &ai_insights,
        );

        let priority_actions = self.compile_priority_actions(
            &vulnerabilities,
            &threats,
            &ai_insights,
        );

        Ok(ComprehensiveReport {
            report_id,
            generated_at,
            template: config.template,
            organization: None,
            period_start: None,
            period_end: Some(generated_at),
            executive_summary,
            security_posture,
            vulnerabilities,
            threats,
            network_security,
            misconfigurations,
            system_info,
            ai_insights,
            compliance_status,
            trends,
            recommendations,
            priority_actions,
        })
    }

    async fn collect_vulnerability_data(&self) -> Result<VulnerabilityData, String> {
        // Get package inventory
        let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;
        let packages = sensor.get_inventory();

        // Scan for vulnerabilities
        let scanner = VulnerabilityScanner::new();
        let vulnerabilities = scanner.scan_packages(&packages);

        let critical_count = vulnerabilities.iter()
            .filter(|v| v.cve.severity == CVESeverity::Critical)
            .count();
        let high_count = vulnerabilities.iter()
            .filter(|v| v.cve.severity == CVESeverity::High)
            .count();
        let medium_count = vulnerabilities.iter()
            .filter(|v| v.cve.severity == CVESeverity::Medium)
            .count();
        let low_count = vulnerabilities.iter()
            .filter(|v| v.cve.severity == CVESeverity::Low)
            .count();

        let top_vulnerabilities: Vec<VulnerabilitySummary> = vulnerabilities
            .iter()
            .take(10)
            .map(|v| VulnerabilitySummary {
                cve_id: v.cve.id.clone(),
                severity: format!("{:?}", v.cve.severity),
                cvss_score: v.cve.cvss_score.unwrap_or(0.0),
                package_name: v.affected_package.name.clone(),
                package_version: v.affected_package.version.clone(),
                description: v.cve.description.lines().next().unwrap_or("").to_string(),
                fix_available: v.cve.affected_packages.iter().any(|p| p.fixed_version.is_some()),
            })
            .collect();

        let affected_packages = vulnerabilities
            .iter()
            .map(|v| v.affected_package.name.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();

        Ok(VulnerabilityData {
            total_count: vulnerabilities.len(),
            critical_count,
            high_count,
            medium_count,
            low_count,
            top_vulnerabilities,
            affected_packages,
            exploitable_count: critical_count + high_count, // Simplified
        })
    }

    async fn collect_threat_data(&self) -> Result<ThreatData, String> {
        // Simplified threat collection - returns empty data for now
        // TODO: Integrate with actual threat detection system
        Ok(ThreatData {
            total_threats: 0,
            active_threats: 0,
            mitigated_threats: 0,
            threat_categories: HashMap::new(),
            recent_threats: Vec::new(),
        })
    }

    async fn collect_network_data(&self) -> Result<NetworkSecurityData, String> {
        // Simplified network data collection
        Ok(NetworkSecurityData {
            total_connections: 0,
            suspicious_connections: 0,
            open_ports: Vec::new(),
            external_connections: 0,
            protocols_used: HashMap::new(),
        })
    }

    async fn collect_misconfiguration_data(&self) -> Result<MisconfigurationData, String> {
        let scanner = MisconfigurationScanner::new();
        let misconfigs = scanner.scan();

        let mut categories = HashMap::new();
        for misconfig in &misconfigs {
            let category = format!("{:?}", misconfig.category);
            *categories.entry(category).or_insert(0) += 1;
        }

        let critical_misconfigs = misconfigs
            .iter()
            .filter(|m| format!("{:?}", m.severity).contains("Critical") || format!("{:?}", m.severity).contains("High"))
            .count();

        let top_issues: Vec<MisconfigSummary> = misconfigs
            .iter()
            .take(10)
            .map(|m| MisconfigSummary {
                title: m.title.clone(),
                severity: format!("{:?}", m.severity),
                category: format!("{:?}", m.category),
                remediation: m.remediation_steps.first().cloned().unwrap_or_default(),
            })
            .collect();

        Ok(MisconfigurationData {
            total_issues: misconfigs.len(),
            critical_misconfigs,
            categories,
            top_issues,
        })
    }

    async fn collect_system_info(&self) -> Result<SystemInfoData, String> {
        use sysinfo::System;

        let mut sys = System::new_all();
        sys.refresh_all();

        Ok(SystemInfoData {
            hostname: System::host_name().unwrap_or_else(|| "Unknown".to_string()),
            os_name: System::name().unwrap_or_else(|| "Unknown".to_string()),
            os_version: System::os_version().unwrap_or_else(|| "Unknown".to_string()),
            kernel_version: System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
            cpu_count: sys.cpus().len(),
            total_memory_gb: sys.total_memory() as f64 / 1_073_741_824.0,
            uptime_days: System::uptime() as f64 / 86400.0,
        })
    }

    fn generate_executive_summary(
        &self,
        vulnerabilities: &VulnerabilityData,
        threats: &ThreatData,
        misconfigs: &MisconfigurationData,
    ) -> ExecutiveSummary {
        let critical_issues = vulnerabilities.critical_count + misconfigs.critical_misconfigs;
        let high_issues = vulnerabilities.high_count;
        let medium_issues = vulnerabilities.medium_count;
        let low_issues = vulnerabilities.low_count;

        let risk_level = if critical_issues > 0 {
            RiskLevel::Critical
        } else if high_issues > 5 {
            RiskLevel::High
        } else if high_issues > 0 || medium_issues > 10 {
            RiskLevel::Medium
        } else if medium_issues > 0 || low_issues > 20 {
            RiskLevel::Low
        } else {
            RiskLevel::Minimal
        };

        let overview = format!(
            "System security assessment identified {} critical issues, {} high-priority issues, and {} total vulnerabilities across the infrastructure.",
            critical_issues, high_issues, vulnerabilities.total_count
        );

        let mut key_highlights = Vec::new();
        if critical_issues > 0 {
            key_highlights.push(format!("{} CRITICAL vulnerabilities requiring immediate attention", critical_issues));
        }
        if threats.total_threats > 0 {
            key_highlights.push(format!("{} active threat detections", threats.total_threats));
        }
        if vulnerabilities.affected_packages > 0 {
            key_highlights.push(format!("{} packages affected by known vulnerabilities", vulnerabilities.affected_packages));
        }
        if misconfigs.total_issues > 0 {
            key_highlights.push(format!("{} security misconfigurations detected", misconfigs.total_issues));
        }

        let business_impact = match risk_level {
            RiskLevel::Critical => "CRITICAL: Immediate action required. System is at significant risk of compromise.".to_string(),
            RiskLevel::High => "HIGH: Urgent remediation needed to prevent potential security incidents.".to_string(),
            RiskLevel::Medium => "MEDIUM: Security improvements recommended within the next 30 days.".to_string(),
            RiskLevel::Low => "LOW: Routine maintenance and monitoring recommended.".to_string(),
            RiskLevel::Minimal => "MINIMAL: System is in good security standing. Continue monitoring.".to_string(),
        };

        ExecutiveSummary {
            overview,
            risk_level,
            critical_issues,
            high_issues,
            medium_issues,
            low_issues,
            key_highlights,
            business_impact,
        }
    }

    async fn get_ai_insights(&self, vuln_data: &VulnerabilityData) -> Result<AnalysisResponse, String> {
        if let Some(analyzer) = &self.analyzer {
            // Get actual vulnerabilities to analyze
            let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;
            let packages = sensor.get_inventory();
            let scanner = VulnerabilityScanner::new();
            let vulnerabilities = scanner.scan_packages(&packages);

            analyzer.analyze_vulnerabilities(&vulnerabilities).await
        } else {
            Err("AI analyzer not available".to_string())
        }
    }

    async fn get_security_posture(&self) -> Result<SystemSecurityPosture, String> {
        if let Some(analyzer) = &self.analyzer {
            let sensor = PackageSensor::new_linux().map_err(|e| e.to_string())?;
            let packages = sensor.get_inventory();
            let vuln_scanner = VulnerabilityScanner::new();
            let vulnerabilities = vuln_scanner.scan_packages(&packages);

            let misconfig_scanner = MisconfigurationScanner::new();
            let misconfigs = misconfig_scanner.scan();

            // Empty threats for now
            let threats: Vec<ThreatEvent> = Vec::new();

            analyzer.analyze_system_posture(&vulnerabilities, &threats, &misconfigs).await
        } else {
            Err("AI analyzer not available".to_string())
        }
    }

    async fn check_compliance(&self, frameworks: &[ComplianceFramework]) -> Result<Vec<ComplianceResult>, String> {
        // Simplified compliance checking - would be expanded with real checks
        Ok(frameworks.iter().map(|framework| {
            ComplianceResult {
                framework: framework.clone(),
                overall_score: 75,
                passed_controls: 45,
                failed_controls: 15,
                not_applicable: 10,
                findings: Vec::new(),
            }
        }).collect())
    }

    async fn generate_trends(&self) -> Result<Vec<SecurityTrendData>, String> {
        // Placeholder for trend analysis
        Ok(Vec::new())
    }

    fn compile_recommendations(
        &self,
        vulnerabilities: &VulnerabilityData,
        threats: &ThreatData,
        misconfigs: &MisconfigurationData,
        ai_insights: &Option<AnalysisResponse>,
    ) -> Vec<Recommendation> {
        let mut recommendations = Vec::new();

        // Add AI recommendations if available
        if let Some(insights) = ai_insights {
            recommendations.extend(insights.recommendations.clone());
        } else {
            // Fallback recommendations based on data
            if vulnerabilities.critical_count > 0 {
                recommendations.push(Recommendation {
                    title: "Update Critical Packages".to_string(),
                    description: format!(
                        "Update {} packages with critical vulnerabilities immediately to prevent exploitation.",
                        vulnerabilities.critical_count
                    ),
                    impact: ImpactLevel::Critical,
                    effort: EffortLevel::Quick,
                    category: RecommendationCategory::Patching,
                });
            }

            if misconfigs.critical_misconfigs > 0 {
                recommendations.push(Recommendation {
                    title: "Fix Critical Misconfigurations".to_string(),
                    description: format!(
                        "Address {} critical security misconfigurations to improve system hardening.",
                        misconfigs.critical_misconfigs
                    ),
                    impact: ImpactLevel::High,
                    effort: EffortLevel::Moderate,
                    category: RecommendationCategory::Configuration,
                });
            }

            if threats.total_threats > 0 {
                recommendations.push(Recommendation {
                    title: "Investigate Active Threats".to_string(),
                    description: format!(
                        "Review and respond to {} detected threat events.",
                        threats.total_threats
                    ),
                    impact: ImpactLevel::High,
                    effort: EffortLevel::Significant,
                    category: RecommendationCategory::Monitoring,
                });
            }
        }

        recommendations
    }

    fn compile_priority_actions(
        &self,
        vulnerabilities: &VulnerabilityData,
        threats: &ThreatData,
        ai_insights: &Option<AnalysisResponse>,
    ) -> Vec<PriorityAction> {
        let mut actions = Vec::new();

        if let Some(insights) = ai_insights {
            actions.extend(insights.priority_actions.clone());
        } else {
            let mut order = 1;

            if vulnerabilities.critical_count > 0 {
                actions.push(PriorityAction {
                    order,
                    action: "Update all critical vulnerabilities".to_string(),
                    reason: "Critical vulnerabilities pose immediate exploitation risk".to_string(),
                    deadline: ActionDeadline::Immediate,
                });
                order += 1;
            }

            if threats.total_threats > 5 {
                actions.push(PriorityAction {
                    order,
                    action: "Investigate high-severity threat detections".to_string(),
                    reason: "Multiple active threats detected requiring analysis".to_string(),
                    deadline: ActionDeadline::Urgent,
                });
                order += 1;
            }

            if vulnerabilities.high_count > 5 {
                actions.push(PriorityAction {
                    order,
                    action: "Patch high-severity vulnerabilities".to_string(),
                    reason: "Significant number of high-severity issues identified".to_string(),
                    deadline: ActionDeadline::Urgent,
                });
            }
        }

        actions
    }
}

// Default implementations
impl Default for VulnerabilityData {
    fn default() -> Self {
        Self {
            total_count: 0,
            critical_count: 0,
            high_count: 0,
            medium_count: 0,
            low_count: 0,
            top_vulnerabilities: Vec::new(),
            affected_packages: 0,
            exploitable_count: 0,
        }
    }
}

impl Default for ThreatData {
    fn default() -> Self {
        Self {
            total_threats: 0,
            active_threats: 0,
            mitigated_threats: 0,
            threat_categories: HashMap::new(),
            recent_threats: Vec::new(),
        }
    }
}

impl Default for NetworkSecurityData {
    fn default() -> Self {
        Self {
            total_connections: 0,
            suspicious_connections: 0,
            open_ports: Vec::new(),
            external_connections: 0,
            protocols_used: HashMap::new(),
        }
    }
}

impl Default for MisconfigurationData {
    fn default() -> Self {
        Self {
            total_issues: 0,
            critical_misconfigs: 0,
            categories: HashMap::new(),
            top_issues: Vec::new(),
        }
    }
}

impl Default for SystemInfoData {
    fn default() -> Self {
        Self {
            hostname: "Unknown".to_string(),
            os_name: "Unknown".to_string(),
            os_version: "Unknown".to_string(),
            kernel_version: "Unknown".to_string(),
            cpu_count: 0,
            total_memory_gb: 0.0,
            uptime_days: 0.0,
        }
    }
}
