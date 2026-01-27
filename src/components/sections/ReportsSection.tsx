import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  ReportTemplate,
  ReportConfiguration,
  ComprehensiveReport,
  SavedReport,
  ExportFormat,
  ComplianceFramework,
  ReportGenerationProgress
} from '../../types/reports';
import {
  FileText,
  Download,
  Eye,
  Settings,
  Calendar,
  Clock,
  TrendingUp,
  Shield,
  AlertTriangle,
  CheckCircle,
  Sparkles,
  RefreshCw,
  Save,
  Trash2,
  ExternalLink
} from 'lucide-react';

const ReportsSection: React.FC = () => {
  const [activeView, setActiveView] = useState<'quick' | 'custom' | 'history' | 'preview'>('quick');
  const [selectedTemplate, setSelectedTemplate] = useState<ReportTemplate>('executive');
  const [reportConfig, setReportConfig] = useState<ReportConfiguration>({
    template: 'executive',
    include_ai_analysis: true,
    include_vulnerabilities: true,
    include_threats: true,
    include_network: true,
    include_misconfigurations: true,
    include_system_info: true,
    include_trends: true,
    compliance_frameworks: [],
  });

  const [generating, setGenerating] = useState(false);
  const [progress, setProgress] = useState<ReportGenerationProgress | null>(null);
  const [currentReport, setCurrentReport] = useState<ComprehensiveReport | null>(null);
  const [savedReports, setSavedReports] = useState<SavedReport[]>([]);
  const [previewHtml, setPreviewHtml] = useState<string>('');
  const [error, setError] = useState<string | null>(null);

  // Load saved reports from localStorage on mount
  useEffect(() => {
    const saved = localStorage.getItem('custos_reports');
    if (saved) {
      try {
        setSavedReports(JSON.parse(saved));
      } catch (e) {
        console.error('Failed to load saved reports:', e);
      }
    }
  }, []);

  const generateReport = async () => {
    setGenerating(true);
    setError(null);
    setProgress({ phase: 'initializing', progress: 0, current_task: 'Starting report generation...' });

    try {
      // Simulate progress updates
      const progressInterval = setInterval(() => {
        setProgress(prev => {
          if (!prev) return null;
          const newProgress = Math.min(prev.progress + 10, 90);
          return {
            ...prev,
            progress: newProgress,
            current_task: getProgressMessage(newProgress),
          };
        });
      }, 500);

      const report = await invoke<ComprehensiveReport>('generate_security_report', { config: reportConfig });

      clearInterval(progressInterval);
      setProgress({ phase: 'complete', progress: 100, current_task: 'Report generated successfully!' });

      setCurrentReport(report);
      setActiveView('preview');

      // Generate HTML preview
      const html = await invoke<string>('export_report_html', { report });
      setPreviewHtml(html);

      setTimeout(() => setProgress(null), 2000);
    } catch (err) {
      setError(`Failed to generate report: ${err}`);
      setProgress(null);
      console.error(err);
    } finally {
      setGenerating(false);
    }
  };

  const getProgressMessage = (progress: number): string => {
    if (progress < 20) return 'Collecting system data...';
    if (progress < 40) return 'Scanning vulnerabilities...';
    if (progress < 60) return 'Analyzing threats...';
    if (progress < 80) return 'Running AI analysis...';
    return 'Finalizing report...';
  };

  const exportReport = async (format: ExportFormat) => {
    if (!currentReport) return;

    try {
      let content: string;
      let fileExtension: string;
      let mimeType: string;

      switch (format) {
        case 'html':
          content = await invoke<string>('export_report_html', { report: currentReport });
          fileExtension = 'html';
          mimeType = 'text/html';
          break;
        case 'markdown':
          content = await invoke<string>('export_report_markdown', { report: currentReport });
          fileExtension = 'md';
          mimeType = 'text/markdown';
          break;
        case 'json':
          content = await invoke<string>('export_report_json', { report: currentReport });
          fileExtension = 'json';
          mimeType = 'application/json';
          break;
        default:
          throw new Error(`Unsupported format: ${format}`);
      }

      // Create download
      const blob = new Blob([content], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `security-report-${currentReport.report_id}.${fileExtension}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(`Failed to export report: ${err}`);
      console.error(err);
    }
  };

  const saveReport = () => {
    if (!currentReport) return;

    const savedReport: SavedReport = {
      id: currentReport.report_id,
      name: `${reportConfig.template} Report - ${new Date(currentReport.generated_at).toLocaleDateString()}`,
      template: reportConfig.template,
      generated_at: currentReport.generated_at,
      report: currentReport,
      exported_formats: [],
    };

    const updated = [...savedReports, savedReport];
    setSavedReports(updated);
    localStorage.setItem('custos_reports', JSON.stringify(updated));
  };

  const deleteReport = (id: string) => {
    const updated = savedReports.filter(r => r.id !== id);
    setSavedReports(updated);
    localStorage.setItem('custos_reports', JSON.stringify(updated));
  };

  const loadSavedReport = (report: SavedReport) => {
    setCurrentReport(report.report);
    setReportConfig({
      template: report.template,
      include_ai_analysis: true,
      include_vulnerabilities: true,
      include_threats: true,
      include_network: true,
      include_misconfigurations: true,
      include_system_info: true,
      include_trends: true,
      compliance_frameworks: [],
    });
    setActiveView('preview');

    // Generate HTML preview
    invoke<string>('export_report_html', { report: report.report })
      .then(html => setPreviewHtml(html))
      .catch(err => console.error('Failed to generate preview:', err));
  };

  const templates = [
    {
      id: 'executive' as ReportTemplate,
      name: 'Executive Summary',
      description: 'High-level overview for leadership and stakeholders',
      icon: TrendingUp,
      color: 'from-blue-500 to-purple-600',
      features: ['Risk overview', 'Business impact', 'Key metrics', 'Priority actions']
    },
    {
      id: 'technical' as ReportTemplate,
      name: 'Technical Analysis',
      description: 'Detailed technical findings for security teams',
      icon: Shield,
      color: 'from-green-500 to-teal-600',
      features: ['CVE details', 'Exploit analysis', 'Technical recommendations', 'Remediation steps']
    },
    {
      id: 'compliance' as ReportTemplate,
      name: 'Compliance Report',
      description: 'Regulatory compliance assessment and gaps',
      icon: CheckCircle,
      color: 'from-indigo-500 to-blue-600',
      features: ['Framework mapping', 'Control status', 'Gap analysis', 'Audit trail']
    },
    {
      id: 'incident' as ReportTemplate,
      name: 'Incident Report',
      description: 'Security incident documentation and response',
      icon: AlertTriangle,
      color: 'from-red-500 to-orange-600',
      features: ['Timeline', 'Impact assessment', 'Root cause', 'Response actions']
    },
    {
      id: 'comprehensive' as ReportTemplate,
      name: 'Comprehensive',
      description: 'Complete security analysis with all details',
      icon: FileText,
      color: 'from-purple-500 to-pink-600',
      features: ['All sections', 'AI insights', 'Full data', 'Extended analysis']
    },
  ];

  const complianceOptions: { id: ComplianceFramework; name: string; description: string }[] = [
    { id: 'cis_benchmark', name: 'CIS Benchmark', description: 'Center for Internet Security' },
    { id: 'nist_csf', name: 'NIST CSF', description: 'Cybersecurity Framework' },
    { id: 'pci_dss', name: 'PCI DSS', description: 'Payment Card Industry' },
    { id: 'hipaa', name: 'HIPAA', description: 'Health Insurance Portability' },
    { id: 'iso27001', name: 'ISO 27001', description: 'Information Security Management' },
    { id: 'gdpr', name: 'GDPR', description: 'General Data Protection Regulation' },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white flex items-center gap-3">
            <FileText className="w-8 h-8 text-blue-600" />
            Security Reports
          </h2>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Generate comprehensive security reports with AI-powered insights
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setActiveView('quick')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeView === 'quick'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
            }`}
          >
            Quick Reports
          </button>
          <button
            onClick={() => setActiveView('custom')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeView === 'custom'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
            }`}
          >
            <Settings className="w-4 h-4 inline mr-2" />
            Custom Builder
          </button>
          <button
            onClick={() => setActiveView('history')}
            className={`px-4 py-2 rounded-lg font-medium transition-all ${
              activeView === 'history'
                ? 'bg-blue-600 text-white shadow-lg'
                : 'bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700'
            }`}
          >
            <Clock className="w-4 h-4 inline mr-2" />
            History ({savedReports.length})
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
          <p className="text-red-700 dark:text-red-300 text-sm">{error}</p>
        </div>
      )}

      {/* Progress Bar */}
      {progress && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <RefreshCw className="w-5 h-5 text-blue-600 animate-spin" />
              <div>
                <h3 className="font-semibold text-gray-900 dark:text-white">Generating Report</h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">{progress.current_task}</p>
              </div>
            </div>
            <span className="text-lg font-bold text-blue-600">{progress.progress}%</span>
          </div>
          <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3">
            <div
              className="bg-gradient-to-r from-blue-500 to-purple-600 h-3 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${progress.progress}%` }}
            />
          </div>
        </div>
      )}

      {/* Quick Reports View */}
      {activeView === 'quick' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {templates.map((template) => (
            <div
              key={template.id}
              className="bg-white dark:bg-gray-800 rounded-xl p-6 border-2 border-gray-200 dark:border-gray-700 hover:border-blue-500 dark:hover:border-blue-500 transition-all cursor-pointer group"
              onClick={() => {
                setReportConfig({ ...reportConfig, template: template.id });
                setSelectedTemplate(template.id);
              }}
            >
              <div className={`w-14 h-14 rounded-xl bg-gradient-to-br ${template.color} flex items-center justify-center mb-4 group-hover:scale-110 transition-transform`}>
                <template.icon className="w-7 h-7 text-white" />
              </div>
              <h3 className="text-xl font-bold text-gray-900 dark:text-white mb-2">{template.name}</h3>
              <p className="text-gray-600 dark:text-gray-400 text-sm mb-4">{template.description}</p>

              <div className="space-y-2 mb-4">
                {template.features.map((feature, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    {feature}
                  </div>
                ))}
              </div>

              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setReportConfig({ ...reportConfig, template: template.id });
                  generateReport();
                }}
                disabled={generating}
                className={`w-full py-3 rounded-lg font-semibold transition-all ${
                  generating
                    ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 cursor-not-allowed'
                    : `bg-gradient-to-r ${template.color} text-white hover:shadow-lg hover:scale-105`
                }`}
              >
                {generating ? 'Generating...' : 'Generate Report'}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Custom Builder View */}
      {activeView === 'custom' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Configuration Panel */}
          <div className="lg:col-span-2 space-y-6">
            {/* Template Selection */}
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Report Template</h3>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {templates.map((template) => (
                  <button
                    key={template.id}
                    onClick={() => setReportConfig({ ...reportConfig, template: template.id })}
                    className={`p-4 rounded-lg border-2 transition-all ${
                      reportConfig.template === template.id
                        ? 'border-blue-500 bg-blue-50 dark:bg-blue-900/20'
                        : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                    }`}
                  >
                    <template.icon className={`w-6 h-6 mb-2 ${
                      reportConfig.template === template.id ? 'text-blue-600' : 'text-gray-600 dark:text-gray-400'
                    }`} />
                    <div className="text-sm font-medium text-gray-900 dark:text-white">{template.name}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Sections to Include */}
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Sections to Include</h3>
              <div className="space-y-3">
                {[
                  { key: 'include_ai_analysis', label: 'AI Analysis & Insights', icon: Sparkles },
                  { key: 'include_vulnerabilities', label: 'Vulnerability Assessment', icon: Shield },
                  { key: 'include_threats', label: 'Threat Detection', icon: AlertTriangle },
                  { key: 'include_network', label: 'Network Security', icon: TrendingUp },
                  { key: 'include_misconfigurations', label: 'Configuration Issues', icon: Settings },
                  { key: 'include_system_info', label: 'System Information', icon: FileText },
                  { key: 'include_trends', label: 'Security Trends', icon: TrendingUp },
                ].map((section) => (
                  <label
                    key={section.key}
                    className="flex items-center gap-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={reportConfig[section.key as keyof ReportConfiguration] as boolean}
                      onChange={(e) => setReportConfig({ ...reportConfig, [section.key]: e.target.checked })}
                      className="w-5 h-5 text-blue-600 rounded focus:ring-blue-500"
                    />
                    <section.icon className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                    <span className="flex-1 text-gray-900 dark:text-white font-medium">{section.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Compliance Frameworks */}
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Compliance Frameworks</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {complianceOptions.map((framework) => (
                  <label
                    key={framework.id}
                    className="flex items-start gap-3 p-3 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700/50 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={reportConfig.compliance_frameworks.includes(framework.id)}
                      onChange={(e) => {
                        const frameworks = e.target.checked
                          ? [...reportConfig.compliance_frameworks, framework.id]
                          : reportConfig.compliance_frameworks.filter(f => f !== framework.id);
                        setReportConfig({ ...reportConfig, compliance_frameworks: frameworks });
                      }}
                      className="w-5 h-5 text-blue-600 rounded focus:ring-blue-500 mt-0.5"
                    />
                    <div className="flex-1">
                      <div className="font-medium text-gray-900 dark:text-white">{framework.name}</div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">{framework.description}</div>
                    </div>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Summary & Actions */}
          <div className="space-y-6">
            {/* Configuration Summary */}
            <div className="bg-gradient-to-br from-blue-50 to-purple-50 dark:from-blue-900/20 dark:to-purple-900/20 rounded-lg p-6 border border-blue-200 dark:border-blue-800">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Report Summary</h3>
              <div className="space-y-3 text-sm">
                <div>
                  <span className="text-gray-600 dark:text-gray-400">Template:</span>
                  <span className="ml-2 font-semibold text-gray-900 dark:text-white capitalize">
                    {reportConfig.template.replace('_', ' ')}
                  </span>
                </div>
                <div>
                  <span className="text-gray-600 dark:text-gray-400">Sections:</span>
                  <span className="ml-2 font-semibold text-gray-900 dark:text-white">
                    {Object.entries(reportConfig).filter(([k, v]) => k.startsWith('include_') && v).length}
                  </span>
                </div>
                <div>
                  <span className="text-gray-600 dark:text-gray-400">Compliance:</span>
                  <span className="ml-2 font-semibold text-gray-900 dark:text-white">
                    {reportConfig.compliance_frameworks.length} frameworks
                  </span>
                </div>
              </div>
            </div>

            {/* Generate Button */}
            <button
              onClick={generateReport}
              disabled={generating}
              className={`w-full py-4 rounded-lg font-bold text-lg transition-all ${
                generating
                  ? 'bg-gray-300 dark:bg-gray-700 text-gray-500 cursor-not-allowed'
                  : 'bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:shadow-xl hover:scale-105'
              }`}
            >
              {generating ? (
                <span className="flex items-center justify-center gap-2">
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  Generating...
                </span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  <Sparkles className="w-5 h-5" />
                  Generate Custom Report
                </span>
              )}
            </button>

            {/* Tips */}
            <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
              <h4 className="font-semibold text-gray-900 dark:text-white mb-3">💡 Tips</h4>
              <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
                <li>• Enable AI Analysis for intelligent insights</li>
                <li>• Include compliance frameworks for audit readiness</li>
                <li>• Technical reports include detailed CVE information</li>
                <li>• Executive reports focus on business impact</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* History View */}
      {activeView === 'history' && (
        <div className="space-y-4">
          {savedReports.length === 0 ? (
            <div className="bg-white dark:bg-gray-800 rounded-lg p-12 text-center border border-gray-200 dark:border-gray-700">
              <FileText className="w-16 h-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 dark:text-white mb-2">No Reports Yet</h3>
              <p className="text-gray-600 dark:text-gray-400 mb-6">Generate your first report to see it here</p>
              <button
                onClick={() => setActiveView('quick')}
                className="px-6 py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-colors"
              >
                Create Report
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {savedReports.map((report) => (
                <div
                  key={report.id}
                  className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700 hover:border-blue-500 dark:hover:border-blue-500 transition-all"
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h3 className="font-semibold text-gray-900 dark:text-white mb-1">{report.name}</h3>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        {new Date(report.generated_at).toLocaleString()}
                      </p>
                    </div>
                    <button
                      onClick={() => deleteReport(report.id)}
                      className="p-2 text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>

                  <div className="flex items-center gap-2 mb-4">
                    <span className="px-3 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-xs font-medium rounded-full capitalize">
                      {report.template.replace('_', ' ')}
                    </span>
                  </div>

                  <div className="flex gap-2">
                    <button
                      onClick={() => loadSavedReport(report)}
                      className="flex-1 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700 transition-colors flex items-center justify-center gap-2"
                    >
                      <Eye className="w-4 h-4" />
                      View
                    </button>
                    <button
                      onClick={() => {
                        setCurrentReport(report.report);
                        exportReport('html');
                      }}
                      className="px-3 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Preview View */}
      {activeView === 'preview' && currentReport && (
        <div className="space-y-6">
          {/* Preview Actions */}
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 border border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xl font-bold text-gray-900 dark:text-white">
                  Report Preview - {currentReport.report_id}
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Generated: {new Date(currentReport.generated_at).toLocaleString()}
                </p>
              </div>
              <div className="flex gap-3">
                <button
                  onClick={saveReport}
                  className="px-4 py-2 bg-green-600 text-white rounded-lg font-medium hover:bg-green-700 transition-colors flex items-center gap-2"
                >
                  <Save className="w-4 h-4" />
                  Save
                </button>
                <button
                  onClick={() => exportReport('html')}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg font-medium hover:bg-blue-700 transition-colors flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Download HTML
                </button>
                <button
                  onClick={() => exportReport('markdown')}
                  className="px-4 py-2 bg-purple-600 text-white rounded-lg font-medium hover:bg-purple-700 transition-colors flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Download MD
                </button>
                <button
                  onClick={() => exportReport('json')}
                  className="px-4 py-2 bg-gray-600 text-white rounded-lg font-medium hover:bg-gray-700 transition-colors flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  Download JSON
                </button>
              </div>
            </div>
          </div>

          {/* Preview Iframe */}
          <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
            <div className="p-4 bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-700 flex items-center justify-between">
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Report Preview</span>
              <button
                onClick={() => {
                  const newWindow = window.open();
                  if (newWindow) {
                    newWindow.document.write(previewHtml);
                    newWindow.document.close();
                  }
                }}
                className="text-sm text-blue-600 hover:text-blue-700 flex items-center gap-1"
              >
                <ExternalLink className="w-4 h-4" />
                Open in New Window
              </button>
            </div>
            <div className="p-6" style={{ maxHeight: '800px', overflow: 'auto' }}>
              {previewHtml ? (
                <iframe
                  srcDoc={previewHtml}
                  className="w-full border-0"
                  style={{ minHeight: '600px', height: '100%' }}
                  title="Report Preview"
                  sandbox="allow-same-origin"
                />
              ) : (
                <div className="flex items-center justify-center py-12">
                  <RefreshCw className="w-8 h-8 text-gray-400 animate-spin" />
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ReportsSection;
