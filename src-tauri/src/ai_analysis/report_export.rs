// Report Export - Export reports to various formats with beautiful styling

use super::report_generator::*;
use super::{SystemSecurityPosture, AnalysisResponse, Recommendation, PriorityAction};
use chrono::{Datelike, Timelike};

pub struct ReportExporter;

impl ReportExporter {
    /// Export report as HTML with beautiful styling
    pub fn to_html(report: &ComprehensiveReport) -> String {
        let mut html = String::new();

        // HTML Header
        html.push_str(&Self::html_header(report));

        // Executive Summary
        html.push_str(&Self::html_executive_summary(&report.executive_summary));

        // Security Posture Dashboard
        if let Some(posture) = &report.security_posture {
            html.push_str(&Self::html_security_posture(posture));
        }

        // Vulnerabilities
        if report.vulnerabilities.total_count > 0 {
            html.push_str(&Self::html_vulnerabilities(&report.vulnerabilities));
        }

        // Threats
        if report.threats.total_threats > 0 {
            html.push_str(&Self::html_threats(&report.threats));
        }

        // Misconfigurations
        if report.misconfigurations.total_issues > 0 {
            html.push_str(&Self::html_misconfigurations(&report.misconfigurations));
        }

        // AI Insights
        if let Some(insights) = &report.ai_insights {
            html.push_str(&Self::html_ai_insights(insights));
        }

        // Recommendations
        if !report.recommendations.is_empty() {
            html.push_str(&Self::html_recommendations(&report.recommendations));
        }

        // Priority Actions
        if !report.priority_actions.is_empty() {
            html.push_str(&Self::html_priority_actions(&report.priority_actions));
        }

        // Compliance
        if !report.compliance_status.is_empty() {
            html.push_str(&Self::html_compliance(&report.compliance_status));
        }

        // System Info
        html.push_str(&Self::html_system_info(&report.system_info));

        // HTML Footer
        html.push_str(&Self::html_footer());

        html
    }

    /// Export report as Markdown
    pub fn to_markdown(report: &ComprehensiveReport) -> String {
        let mut md = String::new();

        // Header
        md.push_str(&format!("# 🛡️ Security Report\n\n"));
        md.push_str(&format!("**Report ID:** {}\n\n", report.report_id));
        md.push_str(&format!("**Generated:** {}\n\n", report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")));
        md.push_str(&format!("**Template:** {:?}\n\n", report.template));
        md.push_str("---\n\n");

        // Executive Summary
        md.push_str("## 📊 Executive Summary\n\n");
        md.push_str(&format!("**Risk Level:** {:?}\n\n", report.executive_summary.risk_level));
        md.push_str(&format!("{}\n\n", report.executive_summary.overview));
        md.push_str(&format!("**Business Impact:** {}\n\n", report.executive_summary.business_impact));

        md.push_str("### Issue Summary\n\n");
        md.push_str(&format!("- 🔴 Critical: {}\n", report.executive_summary.critical_issues));
        md.push_str(&format!("- 🟠 High: {}\n", report.executive_summary.high_issues));
        md.push_str(&format!("- 🟡 Medium: {}\n", report.executive_summary.medium_issues));
        md.push_str(&format!("- 🔵 Low: {}\n\n", report.executive_summary.low_issues));

        if !report.executive_summary.key_highlights.is_empty() {
            md.push_str("### Key Highlights\n\n");
            for highlight in &report.executive_summary.key_highlights {
                md.push_str(&format!("- {}\n", highlight));
            }
            md.push_str("\n");
        }

        // Security Posture
        if let Some(posture) = &report.security_posture {
            md.push_str("## 🎯 Security Posture\n\n");
            md.push_str(&format!("**Overall Score:** {}/100\n\n", posture.overall_score));
            md.push_str("| Component | Score |\n");
            md.push_str("|-----------|-------|\n");
            md.push_str(&format!("| Vulnerabilities | {}/100 |\n", posture.vulnerability_score));
            md.push_str(&format!("| Threats | {}/100 |\n", posture.threat_score));
            md.push_str(&format!("| Configuration | {}/100 |\n", posture.configuration_score));
            md.push_str(&format!("| Compliance | {}/100 |\n\n", posture.compliance_score));

            md.push_str(&format!("{}\n\n", posture.summary));
        }

        // Vulnerabilities
        if report.vulnerabilities.total_count > 0 {
            md.push_str("## 🔒 Vulnerabilities\n\n");
            md.push_str(&format!("**Total:** {} vulnerabilities detected\n\n", report.vulnerabilities.total_count));
            md.push_str(&format!("- Critical: {}\n", report.vulnerabilities.critical_count));
            md.push_str(&format!("- High: {}\n", report.vulnerabilities.high_count));
            md.push_str(&format!("- Medium: {}\n", report.vulnerabilities.medium_count));
            md.push_str(&format!("- Low: {}\n\n", report.vulnerabilities.low_count));
            md.push_str(&format!("**Affected Packages:** {}\n\n", report.vulnerabilities.affected_packages));

            if !report.vulnerabilities.top_vulnerabilities.is_empty() {
                md.push_str("### Top Vulnerabilities\n\n");
                for vuln in &report.vulnerabilities.top_vulnerabilities {
                    md.push_str(&format!("#### {} ({})\n\n", vuln.cve_id, vuln.severity));
                    md.push_str(&format!("- **Package:** {} v{}\n", vuln.package_name, vuln.package_version));
                    md.push_str(&format!("- **CVSS Score:** {:.1}\n", vuln.cvss_score));
                    md.push_str(&format!("- **Fix Available:** {}\n", if vuln.fix_available { "Yes" } else { "No" }));
                    md.push_str(&format!("- **Description:** {}\n\n", vuln.description));
                }
            }
        }

        // Threats
        if report.threats.total_threats > 0 {
            md.push_str("## ⚠️ Threat Detection\n\n");
            md.push_str(&format!("**Total Threats:** {}\n\n", report.threats.total_threats));
            md.push_str(&format!("- Active: {}\n", report.threats.active_threats));
            md.push_str(&format!("- Mitigated: {}\n\n", report.threats.mitigated_threats));

            if !report.threats.recent_threats.is_empty() {
                md.push_str("### Recent Threats\n\n");
                for threat in &report.threats.recent_threats {
                    md.push_str(&format!("- **{}** ({}) - {} - {}\n",
                        threat.title,
                        threat.severity,
                        threat.category,
                        threat.timestamp.format("%Y-%m-%d %H:%M")
                    ));
                }
                md.push_str("\n");
            }
        }

        // Misconfigurations
        if report.misconfigurations.total_issues > 0 {
            md.push_str("## ⚙️ Configuration Issues\n\n");
            md.push_str(&format!("**Total Issues:** {}\n\n", report.misconfigurations.total_issues));
            md.push_str(&format!("**Critical Misconfigurations:** {}\n\n", report.misconfigurations.critical_misconfigs));

            if !report.misconfigurations.top_issues.is_empty() {
                md.push_str("### Top Issues\n\n");
                for issue in &report.misconfigurations.top_issues {
                    md.push_str(&format!("#### {} ({})\n\n", issue.title, issue.severity));
                    md.push_str(&format!("- **Category:** {}\n", issue.category));
                    md.push_str(&format!("- **Remediation:** {}\n\n", issue.remediation));
                }
            }
        }

        // AI Insights
        if let Some(insights) = &report.ai_insights {
            md.push_str("## 🤖 AI Analysis\n\n");
            md.push_str(&format!("**Risk Score:** {}/100\n\n", insights.risk_score));
            md.push_str(&format!("{}\n\n", insights.summary));

            if !insights.key_findings.is_empty() {
                md.push_str("### Key Findings\n\n");
                for finding in &insights.key_findings {
                    md.push_str(&format!("- {}\n", finding));
                }
                md.push_str("\n");
            }
        }

        // Recommendations
        if !report.recommendations.is_empty() {
            md.push_str("## 💡 Recommendations\n\n");
            for (i, rec) in report.recommendations.iter().enumerate() {
                md.push_str(&format!("### {}. {} ({:?} Impact, {:?} Effort)\n\n", i + 1, rec.title, rec.impact, rec.effort));
                md.push_str(&format!("{}\n\n", rec.description));
            }
        }

        // Priority Actions
        if !report.priority_actions.is_empty() {
            md.push_str("## ⚡ Priority Actions\n\n");
            for action in &report.priority_actions {
                md.push_str(&format!("{}. **{}** ({:?})\n", action.order, action.action, action.deadline));
                md.push_str(&format!("   {}\n\n", action.reason));
            }
        }

        // System Info
        md.push_str("## 💻 System Information\n\n");
        md.push_str(&format!("- **Hostname:** {}\n", report.system_info.hostname));
        md.push_str(&format!("- **OS:** {} {}\n", report.system_info.os_name, report.system_info.os_version));
        md.push_str(&format!("- **Kernel:** {}\n", report.system_info.kernel_version));
        md.push_str(&format!("- **CPUs:** {}\n", report.system_info.cpu_count));
        md.push_str(&format!("- **Memory:** {:.1} GB\n", report.system_info.total_memory_gb));
        md.push_str(&format!("- **Uptime:** {:.1} days\n\n", report.system_info.uptime_days));

        md.push_str("---\n\n");
        md.push_str("*Generated by Custos Security Platform*\n");

        md
    }

    // HTML Component Generators

    fn html_header(report: &ComprehensiveReport) -> String {
        format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 50px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            font-weight: 700;
        }}
        .header-meta {{
            opacity: 0.9;
            font-size: 0.95rem;
        }}
        .content {{
            padding: 40px;
        }}
        .section {{
            margin-bottom: 40px;
            padding-bottom: 30px;
            border-bottom: 2px solid #e5e7eb;
        }}
        .section:last-child {{
            border-bottom: none;
        }}
        h2 {{
            color: #667eea;
            font-size: 1.8rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        h3 {{
            color: #4b5563;
            font-size: 1.3rem;
            margin: 20px 0 10px 0;
        }}
        .risk-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9rem;
        }}
        .risk-critical {{ background: #fee2e2; color: #991b1b; }}
        .risk-high {{ background: #fed7aa; color: #9a3412; }}
        .risk-medium {{ background: #fef3c7; color: #92400e; }}
        .risk-low {{ background: #dbeafe; color: #1e40af; }}
        .risk-minimal {{ background: #d1fae5; color: #065f46; }}
        .score-card {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .score {{
            background: linear-gradient(135deg, #f3f4f6 0%, #e5e7eb 100%);
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }}
        .score-value {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #667eea;
        }}
        .score-label {{
            color: #6b7280;
            font-size: 0.9rem;
            margin-top: 5px;
        }}
        .issue-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin: 20px 0;
        }}
        .issue-count {{
            background: white;
            border: 2px solid #e5e7eb;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }}
        .issue-number {{
            font-size: 2rem;
            font-weight: 700;
        }}
        .issue-label {{
            font-size: 0.85rem;
            color: #6b7280;
            margin-top: 5px;
        }}
        .critical {{ color: #dc2626; border-color: #fca5a5; background: #fef2f2; }}
        .high {{ color: #ea580c; border-color: #fdba74; background: #fff7ed; }}
        .medium {{ color: #d97706; border-color: #fcd34d; background: #fefce8; }}
        .low {{ color: #2563eb; border-color: #93c5fd; background: #eff6ff; }}
        .card {{
            background: #f9fafb;
            border: 1px solid #e5e7eb;
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
        }}
        .card-title {{
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 10px;
        }}
        .highlight-box {{
            background: linear-gradient(135deg, #667eea15 0%, #764ba215 100%);
            border-left: 4px solid #667eea;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        ul {{
            margin-left: 20px;
            margin-top: 10px;
        }}
        li {{
            margin: 8px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }}
        th {{
            background: #f3f4f6;
            font-weight: 600;
            color: #374151;
        }}
        .footer {{
            background: #f9fafb;
            padding: 30px;
            text-align: center;
            color: #6b7280;
            font-size: 0.9rem;
        }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Report</h1>
            <div class="header-meta">
                <div>Report ID: {}</div>
                <div>Generated: {}</div>
                <div>Template: {:?}</div>
            </div>
        </div>
        <div class="content">
"#,
            report.generated_at.format("%Y%m%d"),
            report.report_id,
            report.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
            report.template
        )
    }

    fn html_executive_summary(summary: &ExecutiveSummary) -> String {
        let risk_class = match summary.risk_level {
            RiskLevel::Critical => "risk-critical",
            RiskLevel::High => "risk-high",
            RiskLevel::Medium => "risk-medium",
            RiskLevel::Low => "risk-low",
            RiskLevel::Minimal => "risk-minimal",
        };

        format!(r#"
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="highlight-box">
                <div style="margin-bottom: 15px;">
                    <span class="risk-badge {}">Risk Level: {:?}</span>
                </div>
                <p style="font-size: 1.1rem; margin: 15px 0;">{}</p>
                <p style="margin-top: 15px;"><strong>{}</strong></p>
            </div>

            <div class="issue-grid">
                <div class="issue-count critical">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">Critical</div>
                </div>
                <div class="issue-count high">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">High</div>
                </div>
                <div class="issue-count medium">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">Medium</div>
                </div>
                <div class="issue-count low">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">Low</div>
                </div>
            </div>

            {}
        </div>
        "#,
            risk_class,
            summary.risk_level,
            summary.overview,
            summary.business_impact,
            summary.critical_issues,
            summary.high_issues,
            summary.medium_issues,
            summary.low_issues,
            if !summary.key_highlights.is_empty() {
                format!(r#"
                <h3>Key Highlights</h3>
                <ul>
                    {}
                </ul>
                "#, summary.key_highlights.iter().map(|h| format!("<li>{}</li>", h)).collect::<Vec<_>>().join("\n"))
            } else {
                String::new()
            }
        )
    }

    fn html_security_posture(posture: &SystemSecurityPosture) -> String {
        format!(r#"
        <div class="section">
            <h2>🎯 Security Posture</h2>
            <div class="score-card">
                <div class="score">
                    <div class="score-value">{}</div>
                    <div class="score-label">Overall Score</div>
                </div>
                <div class="score">
                    <div class="score-value">{}</div>
                    <div class="score-label">Vulnerabilities</div>
                </div>
                <div class="score">
                    <div class="score-value">{}</div>
                    <div class="score-label">Threats</div>
                </div>
                <div class="score">
                    <div class="score-value">{}</div>
                    <div class="score-label">Configuration</div>
                </div>
                <div class="score">
                    <div class="score-value">{}</div>
                    <div class="score-label">Compliance</div>
                </div>
            </div>
            <p style="margin-top: 20px; font-size: 1.05rem;">{}</p>
        </div>
        "#,
            posture.overall_score,
            posture.vulnerability_score,
            posture.threat_score,
            posture.configuration_score,
            posture.compliance_score,
            posture.summary
        )
    }

    fn html_vulnerabilities(vuln: &VulnerabilityData) -> String {
        let mut html = format!(r#"
        <div class="section">
            <h2>🔒 Vulnerabilities</h2>
            <p><strong>Total Vulnerabilities:</strong> {}</p>
            <p><strong>Affected Packages:</strong> {}</p>

            <div class="issue-grid">
                <div class="issue-count critical">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">Critical</div>
                </div>
                <div class="issue-count high">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">High</div>
                </div>
                <div class="issue-count medium">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">Medium</div>
                </div>
                <div class="issue-count low">
                    <div class="issue-number">{}</div>
                    <div class="issue-label">Low</div>
                </div>
            </div>
        "#,
            vuln.total_count,
            vuln.affected_packages,
            vuln.critical_count,
            vuln.high_count,
            vuln.medium_count,
            vuln.low_count
        );

        if !vuln.top_vulnerabilities.is_empty() {
            html.push_str("<h3>Top Vulnerabilities</h3>");
            for v in &vuln.top_vulnerabilities {
                html.push_str(&format!(r#"
                <div class="card">
                    <div class="card-title">{} ({})</div>
                    <p><strong>Package:</strong> {} v{}</p>
                    <p><strong>CVSS Score:</strong> {:.1}</p>
                    <p><strong>Fix Available:</strong> {}</p>
                    <p style="margin-top: 10px;">{}</p>
                </div>
                "#,
                    v.cve_id,
                    v.severity,
                    v.package_name,
                    v.package_version,
                    v.cvss_score,
                    if v.fix_available { "Yes ✓" } else { "No ✗" },
                    v.description
                ));
            }
        }

        html.push_str("</div>");
        html
    }

    fn html_threats(threats: &ThreatData) -> String {
        let mut html = format!(r#"
        <div class="section">
            <h2>⚠️ Threat Detection</h2>
            <p><strong>Total Threats:</strong> {}</p>
            <p><strong>Active:</strong> {} | <strong>Mitigated:</strong> {}</p>
        "#,
            threats.total_threats,
            threats.active_threats,
            threats.mitigated_threats
        );

        if !threats.recent_threats.is_empty() {
            html.push_str("<h3>Recent Threats</h3>");
            for threat in &threats.recent_threats {
                html.push_str(&format!(r#"
                <div class="card">
                    <div class="card-title">{} ({})</div>
                    <p><strong>Category:</strong> {}</p>
                    <p><strong>Detected:</strong> {}</p>
                    <p><strong>Status:</strong> {}</p>
                </div>
                "#,
                    threat.title,
                    threat.severity,
                    threat.category,
                    threat.timestamp.format("%Y-%m-%d %H:%M"),
                    threat.status
                ));
            }
        }

        html.push_str("</div>");
        html
    }

    fn html_misconfigurations(misconfig: &MisconfigurationData) -> String {
        let mut html = format!(r#"
        <div class="section">
            <h2>⚙️ Configuration Issues</h2>
            <p><strong>Total Issues:</strong> {}</p>
            <p><strong>Critical Misconfigurations:</strong> {}</p>
        "#,
            misconfig.total_issues,
            misconfig.critical_misconfigs
        );

        if !misconfig.top_issues.is_empty() {
            html.push_str("<h3>Top Issues</h3>");
            for issue in &misconfig.top_issues {
                html.push_str(&format!(r#"
                <div class="card">
                    <div class="card-title">{} ({})</div>
                    <p><strong>Category:</strong> {}</p>
                    <p><strong>Remediation:</strong> {}</p>
                </div>
                "#,
                    issue.title,
                    issue.severity,
                    issue.category,
                    issue.remediation
                ));
            }
        }

        html.push_str("</div>");
        html
    }

    fn html_ai_insights(insights: &AnalysisResponse) -> String {
        let mut html = format!(r#"
        <div class="section">
            <h2>🤖 AI Analysis</h2>
            <div class="highlight-box">
                <p><strong>Risk Score:</strong> {}/100</p>
                <p style="margin-top: 10px;">{}</p>
            </div>
        "#,
            insights.risk_score,
            insights.summary
        );

        if !insights.key_findings.is_empty() {
            html.push_str("<h3>Key Findings</h3><ul>");
            for finding in &insights.key_findings {
                html.push_str(&format!("<li>{}</li>", finding));
            }
            html.push_str("</ul>");
        }

        html.push_str("</div>");
        html
    }

    fn html_recommendations(recommendations: &[Recommendation]) -> String {
        let mut html = String::from(r#"
        <div class="section">
            <h2>💡 Recommendations</h2>
        "#);

        for (i, rec) in recommendations.iter().enumerate() {
            html.push_str(&format!(r#"
            <div class="card">
                <div class="card-title">{}. {} ({:?} Impact, {:?} Effort)</div>
                <p><strong>Category:</strong> {:?}</p>
                <p style="margin-top: 10px;">{}</p>
            </div>
            "#,
                i + 1,
                rec.title,
                rec.impact,
                rec.effort,
                rec.category,
                rec.description
            ));
        }

        html.push_str("</div>");
        html
    }

    fn html_priority_actions(actions: &[PriorityAction]) -> String {
        let mut html = String::from(r#"
        <div class="section">
            <h2>⚡ Priority Actions</h2>
        "#);

        for action in actions {
            html.push_str(&format!(r#"
            <div class="card">
                <div class="card-title">{}. {} ({:?})</div>
                <p>{}</p>
            </div>
            "#,
                action.order,
                action.action,
                action.deadline,
                action.reason
            ));
        }

        html.push_str("</div>");
        html
    }

    fn html_compliance(compliance: &[ComplianceResult]) -> String {
        let mut html = String::from(r#"
        <div class="section">
            <h2>✅ Compliance Status</h2>
        "#);

        for result in compliance {
            html.push_str(&format!(r#"
            <div class="card">
                <div class="card-title">{:?} - Score: {}/100</div>
                <p><strong>Passed:</strong> {} | <strong>Failed:</strong> {} | <strong>N/A:</strong> {}</p>
            </div>
            "#,
                result.framework,
                result.overall_score,
                result.passed_controls,
                result.failed_controls,
                result.not_applicable
            ));
        }

        html.push_str("</div>");
        html
    }

    fn html_system_info(info: &SystemInfoData) -> String {
        format!(r#"
        <div class="section">
            <h2>💻 System Information</h2>
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Hostname</td><td>{}</td></tr>
                <tr><td>Operating System</td><td>{} {}</td></tr>
                <tr><td>Kernel Version</td><td>{}</td></tr>
                <tr><td>CPU Count</td><td>{}</td></tr>
                <tr><td>Total Memory</td><td>{:.1} GB</td></tr>
                <tr><td>Uptime</td><td>{:.1} days</td></tr>
            </table>
        </div>
        "#,
            info.hostname,
            info.os_name,
            info.os_version,
            info.kernel_version,
            info.cpu_count,
            info.total_memory_gb,
            info.uptime_days
        )
    }

    fn html_footer() -> String {
        String::from(r#"
        </div>
        <div class="footer">
            <p>Generated by Custos Security Platform</p>
            <p style="margin-top: 5px;">© 2024 - Comprehensive Security Analysis</p>
        </div>
    </div>
</body>
</html>
        "#)
    }
}
