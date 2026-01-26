import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  AnalysisResponse,
  SystemSecurityPosture,
  Recommendation,
  PriorityAction,
  ImpactLevel,
  EffortLevel,
  ActionDeadline
} from '../types/ai-analysis';

interface AIAnalysisSectionProps {
  autoAnalyze?: boolean;
}

const AIAnalysisSection: React.FC<AIAnalysisSectionProps> = ({ autoAnalyze = false }) => {
  const [vulnerabilityAnalysis, setVulnerabilityAnalysis] = useState<AnalysisResponse | null>(null);
  const [securityPosture, setSecurityPosture] = useState<SystemSecurityPosture | null>(null);
  const [remediationPlan, setRemediationPlan] = useState<AnalysisResponse | null>(null);

  const [loading, setLoading] = useState<{ [key: string]: boolean }>({});
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'vulnerabilities' | 'posture' | 'remediation'>('vulnerabilities');

  useEffect(() => {
    if (autoAnalyze) {
      analyzeVulnerabilities();
    }
  }, [autoAnalyze]);

  const analyzeVulnerabilities = async () => {
    setLoading({ ...loading, vulnerabilities: true });
    setError(null);
    try {
      const result = await invoke<AnalysisResponse>('analyze_vulnerabilities_with_ai');
      setVulnerabilityAnalysis(result);
    } catch (err) {
      setError(`Failed to analyze vulnerabilities: ${err}`);
      console.error(err);
    } finally {
      setLoading({ ...loading, vulnerabilities: false });
    }
  };

  const analyzeSecurityPosture = async () => {
    setLoading({ ...loading, posture: true });
    setError(null);
    try {
      const result = await invoke<SystemSecurityPosture>('analyze_security_posture');
      setSecurityPosture(result);
    } catch (err) {
      setError(`Failed to analyze security posture: ${err}`);
      console.error(err);
    } finally {
      setLoading({ ...loading, posture: false });
    }
  };

  const generateRemediationPlan = async () => {
    setLoading({ ...loading, remediation: true });
    setError(null);
    try {
      const result = await invoke<AnalysisResponse>('generate_remediation_plan');
      setRemediationPlan(result);
    } catch (err) {
      setError(`Failed to generate remediation plan: ${err}`);
      console.error(err);
    } finally {
      setLoading({ ...loading, remediation: false });
    }
  };

  const getImpactColor = (impact: ImpactLevel): string => {
    switch (impact) {
      case 'critical': return 'text-red-600 bg-red-50 border-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 border-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 border-blue-200';
    }
  };

  const getEffortBadge = (effort: EffortLevel): string => {
    switch (effort) {
      case 'quick': return '🕐 Quick (<1h)';
      case 'moderate': return '🕑 Moderate (1-8h)';
      case 'significant': return '🕓 Significant (1-3d)';
      case 'major': return '🕔 Major (>3d)';
    }
  };

  const getDeadlineBadge = (deadline: ActionDeadline): string => {
    switch (deadline) {
      case 'immediate': return '🔴 Immediate (24h)';
      case 'urgent': return '🟡 Urgent (1w)';
      case 'soon': return '🟢 Soon (1m)';
      case 'planned': return '🔵 Planned (3m)';
    }
  };

  const getScoreColor = (score: number): string => {
    if (score >= 80) return 'text-green-600';
    if (score >= 60) return 'text-yellow-600';
    if (score >= 40) return 'text-orange-600';
    return 'text-red-600';
  };

  const getRiskScoreColor = (score: number): string => {
    if (score >= 75) return 'text-red-600 bg-red-50';
    if (score >= 50) return 'text-orange-600 bg-orange-50';
    if (score >= 25) return 'text-yellow-600 bg-yellow-50';
    return 'text-green-600 bg-green-50';
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">🤖 AI Security Analysis</h2>
          <p className="text-sm text-gray-600 mt-1">Powered by Claude AI</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={analyzeVulnerabilities}
            disabled={loading.vulnerabilities}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading.vulnerabilities ? 'Analyzing...' : '🔍 Analyze Vulnerabilities'}
          </button>
          <button
            onClick={analyzeSecurityPosture}
            disabled={loading.posture}
            className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading.posture ? 'Analyzing...' : '📊 Security Posture'}
          </button>
          <button
            onClick={generateRemediationPlan}
            disabled={loading.remediation}
            className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading.remediation ? 'Generating...' : '🛠️ Remediation Plan'}
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-700 text-sm">{error}</p>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8">
          <button
            onClick={() => setActiveTab('vulnerabilities')}
            className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'vulnerabilities'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Vulnerability Analysis
          </button>
          <button
            onClick={() => setActiveTab('posture')}
            className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'posture'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Security Posture
          </button>
          <button
            onClick={() => setActiveTab('remediation')}
            className={`py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === 'remediation'
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            Remediation Plan
          </button>
        </nav>
      </div>

      {/* Vulnerability Analysis Tab */}
      {activeTab === 'vulnerabilities' && (
        <div className="space-y-6">
          {vulnerabilityAnalysis ? (
            <>
              {/* Risk Score Card */}
              <div className={`p-6 rounded-lg border-2 ${getRiskScoreColor(vulnerabilityAnalysis.risk_score)}`}>
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold">Overall Risk Score</h3>
                    <p className="text-sm opacity-75">Based on severity, exploitability, and exposure</p>
                  </div>
                  <div className="text-right">
                    <div className="text-4xl font-bold">{vulnerabilityAnalysis.risk_score}/100</div>
                    <div className="text-sm mt-1">Confidence: {(vulnerabilityAnalysis.confidence * 100).toFixed(0)}%</div>
                  </div>
                </div>
              </div>

              {/* Executive Summary */}
              <div className="bg-white p-6 rounded-lg border border-gray-200">
                <h3 className="text-lg font-semibold mb-3">📋 Executive Summary</h3>
                <p className="text-gray-700 leading-relaxed">{vulnerabilityAnalysis.summary}</p>
              </div>

              {/* Key Findings */}
              {vulnerabilityAnalysis.key_findings.length > 0 && (
                <div className="bg-white p-6 rounded-lg border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">🔍 Key Findings</h3>
                  <ul className="space-y-2">
                    {vulnerabilityAnalysis.key_findings.map((finding, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <span className="text-blue-600 font-bold mt-1">•</span>
                        <span className="text-gray-700">{finding}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Recommendations */}
              {vulnerabilityAnalysis.recommendations.length > 0 && (
                <div className="bg-white p-6 rounded-lg border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">💡 Recommendations</h3>
                  <div className="space-y-4">
                    {vulnerabilityAnalysis.recommendations.map((rec, idx) => (
                      <div key={idx} className={`p-4 rounded-lg border ${getImpactColor(rec.impact)}`}>
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-semibold">{rec.title}</h4>
                          <div className="flex gap-2 text-xs">
                            <span className="px-2 py-1 bg-white rounded">{getEffortBadge(rec.effort)}</span>
                            <span className="px-2 py-1 bg-white rounded capitalize">{rec.category.replace('_', ' ')}</span>
                          </div>
                        </div>
                        <p className="text-sm opacity-90">{rec.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Priority Actions */}
              {vulnerabilityAnalysis.priority_actions.length > 0 && (
                <div className="bg-white p-6 rounded-lg border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">⚡ Priority Actions</h3>
                  <div className="space-y-3">
                    {vulnerabilityAnalysis.priority_actions
                      .sort((a, b) => a.order - b.order)
                      .map((action) => (
                        <div key={action.order} className="p-4 bg-gray-50 rounded-lg border border-gray-200">
                          <div className="flex items-start gap-3">
                            <span className="flex-shrink-0 w-8 h-8 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold">
                              {action.order}
                            </span>
                            <div className="flex-1">
                              <div className="flex items-center justify-between mb-2">
                                <h4 className="font-semibold text-gray-900">{action.action}</h4>
                                <span className="text-xs px-2 py-1 bg-white rounded border">
                                  {getDeadlineBadge(action.deadline)}
                                </span>
                              </div>
                              <p className="text-sm text-gray-600">{action.reason}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-12 bg-gray-50 rounded-lg border border-gray-200">
              <p className="text-gray-600">Click "Analyze Vulnerabilities" to get AI-powered insights</p>
            </div>
          )}
        </div>
      )}

      {/* Security Posture Tab */}
      {activeTab === 'posture' && (
        <div className="space-y-6">
          {securityPosture ? (
            <>
              {/* Overall Score */}
              <div className="bg-gradient-to-br from-blue-50 to-purple-50 p-8 rounded-lg border-2 border-blue-200">
                <div className="text-center">
                  <h3 className="text-2xl font-bold mb-2">Security Posture Score</h3>
                  <div className={`text-6xl font-bold ${getScoreColor(securityPosture.overall_score)}`}>
                    {securityPosture.overall_score}/100
                  </div>
                  <p className="text-gray-700 mt-4">{securityPosture.summary}</p>
                </div>
              </div>

              {/* Component Scores */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-white p-4 rounded-lg border border-gray-200 text-center">
                  <div className="text-sm text-gray-600 mb-1">Vulnerabilities</div>
                  <div className={`text-3xl font-bold ${getScoreColor(securityPosture.vulnerability_score)}`}>
                    {securityPosture.vulnerability_score}
                  </div>
                </div>
                <div className="bg-white p-4 rounded-lg border border-gray-200 text-center">
                  <div className="text-sm text-gray-600 mb-1">Threats</div>
                  <div className={`text-3xl font-bold ${getScoreColor(securityPosture.threat_score)}`}>
                    {securityPosture.threat_score}
                  </div>
                </div>
                <div className="bg-white p-4 rounded-lg border border-gray-200 text-center">
                  <div className="text-sm text-gray-600 mb-1">Configuration</div>
                  <div className={`text-3xl font-bold ${getScoreColor(securityPosture.configuration_score)}`}>
                    {securityPosture.configuration_score}
                  </div>
                </div>
                <div className="bg-white p-4 rounded-lg border border-gray-200 text-center">
                  <div className="text-sm text-gray-600 mb-1">Compliance</div>
                  <div className={`text-3xl font-bold ${getScoreColor(securityPosture.compliance_score)}`}>
                    {securityPosture.compliance_score}
                  </div>
                </div>
              </div>

              {/* Trends */}
              {securityPosture.trends.length > 0 && (
                <div className="bg-white p-6 rounded-lg border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">📈 Security Trends</h3>
                  <div className="space-y-3">
                    {securityPosture.trends.map((trend, idx) => (
                      <div key={idx} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex-1">
                          <div className="font-medium text-gray-900">{trend.metric}</div>
                          <div className="text-sm text-gray-600">{trend.description}</div>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className={`font-bold ${
                            trend.direction === 'improving' ? 'text-green-600' :
                            trend.direction === 'degrading' ? 'text-red-600' :
                            'text-gray-600'
                          }`}>
                            {trend.direction === 'improving' ? '↗' :
                             trend.direction === 'degrading' ? '↘' : '→'}
                            {Math.abs(trend.change_percentage).toFixed(1)}%
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-12 bg-gray-50 rounded-lg border border-gray-200">
              <p className="text-gray-600">Click "Security Posture" to get comprehensive security assessment</p>
            </div>
          )}
        </div>
      )}

      {/* Remediation Plan Tab */}
      {activeTab === 'remediation' && (
        <div className="space-y-6">
          {remediationPlan ? (
            <>
              {/* Summary */}
              <div className="bg-white p-6 rounded-lg border border-gray-200">
                <h3 className="text-lg font-semibold mb-3">📋 Remediation Summary</h3>
                <p className="text-gray-700 leading-relaxed">{remediationPlan.summary}</p>
              </div>

              {/* Priority Actions */}
              {remediationPlan.priority_actions.length > 0 && (
                <div className="bg-white p-6 rounded-lg border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">⚡ Action Plan</h3>
                  <div className="space-y-3">
                    {remediationPlan.priority_actions
                      .sort((a, b) => a.order - b.order)
                      .map((action) => (
                        <div key={action.order} className="p-4 bg-gradient-to-r from-blue-50 to-purple-50 rounded-lg border border-blue-200">
                          <div className="flex items-start gap-3">
                            <span className="flex-shrink-0 w-10 h-10 bg-blue-600 text-white rounded-full flex items-center justify-center font-bold text-lg">
                              {action.order}
                            </span>
                            <div className="flex-1">
                              <div className="flex items-center justify-between mb-2">
                                <h4 className="font-semibold text-gray-900 text-lg">{action.action}</h4>
                                <span className="text-xs px-3 py-1 bg-white rounded-full border-2">
                                  {getDeadlineBadge(action.deadline)}
                                </span>
                              </div>
                              <p className="text-sm text-gray-700 font-medium">{action.reason}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              )}

              {/* Detailed Recommendations */}
              {remediationPlan.recommendations.length > 0 && (
                <div className="bg-white p-6 rounded-lg border border-gray-200">
                  <h3 className="text-lg font-semibold mb-4">🔧 Detailed Steps</h3>
                  <div className="space-y-4">
                    {remediationPlan.recommendations.map((rec, idx) => (
                      <div key={idx} className={`p-4 rounded-lg border ${getImpactColor(rec.impact)}`}>
                        <div className="flex items-start justify-between mb-2">
                          <h4 className="font-semibold">{rec.title}</h4>
                          <div className="flex gap-2 text-xs">
                            <span className="px-2 py-1 bg-white rounded">{getEffortBadge(rec.effort)}</span>
                          </div>
                        </div>
                        <p className="text-sm opacity-90 whitespace-pre-line">{rec.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-12 bg-gray-50 rounded-lg border border-gray-200">
              <p className="text-gray-600">Click "Remediation Plan" to generate a prioritized fix plan</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default AIAnalysisSection;
