// AI Analysis Types - matches Rust backend structures

export type AnalysisType =
  | 'vulnerability_summary'
  | 'threat_assessment'
  | 'system_posture'
  | 'remediation_plan'
  | 'security_trends';

export type ImpactLevel = 'critical' | 'high' | 'medium' | 'low';
export type EffortLevel = 'quick' | 'moderate' | 'significant' | 'major';
export type ActionDeadline = 'immediate' | 'urgent' | 'soon' | 'planned';
export type TrendDirection = 'improving' | 'stable' | 'degrading';

export type RecommendationCategory =
  | 'patching'
  | 'configuration'
  | 'access_control'
  | 'monitoring'
  | 'network_security'
  | 'application_security'
  | 'data_protection';

export interface Recommendation {
  title: string;
  description: string;
  impact: ImpactLevel;
  effort: EffortLevel;
  category: RecommendationCategory;
}

export interface PriorityAction {
  order: number;
  action: string;
  reason: string;
  deadline: ActionDeadline;
}

export interface AnalysisResponse {
  analysis_type: AnalysisType;
  summary: string;
  key_findings: string[];
  recommendations: Recommendation[];
  priority_actions: PriorityAction[];
  risk_score: number; // 0-100
  confidence: number; // 0.0-1.0
}

export interface SecurityTrend {
  metric: string;
  direction: TrendDirection;
  change_percentage: number;
  description: string;
}

export interface SystemSecurityPosture {
  overall_score: number;
  vulnerability_score: number;
  threat_score: number;
  configuration_score: number;
  compliance_score: number;
  summary: string;
  trends: SecurityTrend[];
}
