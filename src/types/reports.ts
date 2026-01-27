// Comprehensive Report Types - matches Rust backend structures

export type ReportTemplate =
  | 'executive'
  | 'technical'
  | 'compliance'
  | 'incident'
  | 'comprehensive';

export type ExportFormat = 'html' | 'markdown' | 'json' | 'pdf';

export type ComplianceFramework =
  | 'cis_benchmark'
  | 'nist_csf'
  | 'pci_dss'
  | 'hipaa'
  | 'iso27001'
  | 'gdpr';

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'minimal';

export interface ReportConfiguration {
  template: ReportTemplate;
  include_ai_analysis: boolean;
  include_vulnerabilities: boolean;
  include_threats: boolean;
  include_network: boolean;
  include_misconfigurations: boolean;
  include_system_info: boolean;
  include_trends: boolean;
  compliance_frameworks: ComplianceFramework[];
}

export interface ExecutiveSummary {
  overview: string;
  risk_level: RiskLevel;
  critical_issues: number;
  high_issues: number;
  medium_issues: number;
  low_issues: number;
  key_highlights: string[];
  business_impact: string;
}

export interface VulnerabilityData {
  total_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  top_vulnerabilities: VulnerabilitySummary[];
  affected_packages: number;
  exploitable_count: number;
}

export interface VulnerabilitySummary {
  cve_id: string;
  severity: string;
  cvss_score: number;
  package_name: string;
  package_version: string;
  description: string;
  fix_available: boolean;
}

export interface ThreatData {
  total_threats: number;
  active_threats: number;
  mitigated_threats: number;
  threat_categories: Record<string, number>;
  recent_threats: ThreatSummary[];
}

export interface ThreatSummary {
  title: string;
  severity: string;
  category: string;
  timestamp: string;
  status: string;
}

export interface NetworkSecurityData {
  total_connections: number;
  suspicious_connections: number;
  open_ports: number[];
  external_connections: number;
  protocols_used: Record<string, number>;
}

export interface MisconfigurationData {
  total_issues: number;
  critical_misconfigs: number;
  categories: Record<string, number>;
  top_issues: MisconfigSummary[];
}

export interface MisconfigSummary {
  title: string;
  severity: string;
  category: string;
  remediation: string;
}

export interface SystemInfoData {
  hostname: string;
  os_name: string;
  os_version: string;
  kernel_version: string;
  cpu_count: number;
  total_memory_gb: number;
  uptime_days: number;
}

export interface ComplianceResult {
  framework: ComplianceFramework;
  overall_score: number;
  passed_controls: number;
  failed_controls: number;
  not_applicable: number;
  findings: ComplianceFinding[];
}

export interface ComplianceFinding {
  control_id: string;
  control_name: string;
  status: 'pass' | 'fail' | 'partial' | 'not_applicable';
  details: string;
}

export interface SecurityTrendData {
  metric: string;
  current_value: number;
  previous_value?: number;
  change_percentage: number;
  direction: 'improving' | 'stable' | 'degrading';
  time_period: string;
}

export interface ComprehensiveReport {
  report_id: string;
  generated_at: string;
  template: ReportTemplate;
  organization?: string;
  period_start?: string;
  period_end?: string;
  executive_summary: ExecutiveSummary;
  security_posture?: {
    overall_score: number;
    vulnerability_score: number;
    threat_score: number;
    configuration_score: number;
    compliance_score: number;
    summary: string;
    trends: SecurityTrendData[];
  };
  vulnerabilities: VulnerabilityData;
  threats: ThreatData;
  network_security: NetworkSecurityData;
  misconfigurations: MisconfigurationData;
  system_info: SystemInfoData;
  ai_insights?: {
    analysis_type: string;
    summary: string;
    key_findings: string[];
    recommendations: Array<{
      title: string;
      description: string;
      impact: string;
      effort: string;
      category: string;
    }>;
    priority_actions: Array<{
      order: number;
      action: string;
      reason: string;
      deadline: string;
    }>;
    risk_score: number;
    confidence: number;
  };
  compliance_status: ComplianceResult[];
  trends: SecurityTrendData[];
  recommendations: Array<{
    title: string;
    description: string;
    impact: string;
    effort: string;
    category: string;
  }>;
  priority_actions: Array<{
    order: number;
    action: string;
    reason: string;
    deadline: string;
  }>;
}

export interface SavedReport {
  id: string;
  name: string;
  template: ReportTemplate;
  generated_at: string;
  report: ComprehensiveReport;
  exported_formats: ExportFormat[];
}

export interface ReportGenerationProgress {
  phase: string;
  progress: number;
  current_task: string;
  estimated_completion?: number;
}
