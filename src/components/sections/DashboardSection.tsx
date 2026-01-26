import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, CheckCircle2, RefreshCw } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';

// Backend data structures
interface ThreatStats {
  total_threats: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

interface SystemMetrics {
  timestamp: string;
  cpu: {
    usage_percent: number;
  };
  memory: {
    usage_percent: number;
  };
}

interface ThreatEvent {
  id: string;
  timestamp: string;
  severity: string;
  category: string;
  title: string;
  description: string;
}

export const DashboardSection: React.FC = () => {
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null);
  const [recentThreats, setRecentThreats] = useState<ThreatEvent[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [lastScanTime, setLastScanTime] = useState<Date>(new Date());

  // Fetch threat statistics
  const fetchThreatStats = async () => {
    try {
      const stats = await invoke<ThreatStats>('get_threat_statistics');
      setThreatStats(stats);
    } catch (error) {
      console.error('Failed to fetch threat statistics:', error);
    }
  };

  // Fetch system metrics
  const fetchSystemMetrics = async () => {
    try {
      const metrics = await invoke<SystemMetrics>('get_current_metrics');
      setSystemMetrics(metrics);
    } catch (error) {
      console.error('Failed to fetch system metrics:', error);
    }
  };

  // Fetch recent threats
  const fetchRecentThreats = async () => {
    try {
      const threats = await invoke<ThreatEvent[]>('get_recent_threats', { limit: 5 });
      setRecentThreats(threats);
    } catch (error) {
      console.error('Failed to fetch recent threats:', error);
    }
  };

  // Initial data fetch
  useEffect(() => {
    fetchThreatStats();
    fetchSystemMetrics();
    fetchRecentThreats();

    // Refresh data every 10 seconds
    const interval = setInterval(() => {
      fetchThreatStats();
      fetchSystemMetrics();
      fetchRecentThreats();
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  // Calculate security score (0-100)
  const calculateSecurityScore = (): number => {
    if (!threatStats || !systemMetrics) return 95;

    let score = 100;

    // Deduct points for active threats
    const activeThreatCount = threatStats.total_threats;
    score -= Math.min(activeThreatCount * 5, 50); // Max 50 points deduction

    // Deduct points for critical/high severity threats
    const criticalThreats = threatStats.by_severity['Critical'] || 0;
    const highThreats = threatStats.by_severity['High'] || 0;
    score -= criticalThreats * 10;
    score -= highThreats * 5;

    // Deduct points for poor system health
    if (systemMetrics.cpu.usage_percent > 90) score -= 5;
    if (systemMetrics.memory.usage_percent > 90) score -= 5;

    return Math.max(0, Math.min(100, score));
  };

  // Determine system health status
  const getSystemHealthStatus = (): { label: string; color: string; bg: string } => {
    if (!systemMetrics) return { label: 'Unknown', color: 'text-gray-600 dark:text-gray-400', bg: 'bg-gray-50 dark:bg-gray-900/20' };

    const cpuUsage = systemMetrics.cpu.usage_percent;
    const memUsage = systemMetrics.memory.usage_percent;

    if (cpuUsage > 90 || memUsage > 90) {
      return { label: 'Critical', color: 'text-red-600 dark:text-red-400', bg: 'bg-red-50 dark:bg-red-900/20' };
    } else if (cpuUsage > 75 || memUsage > 75) {
      return { label: 'Warning', color: 'text-yellow-600 dark:text-yellow-400', bg: 'bg-yellow-50 dark:bg-yellow-900/20' };
    } else {
      return { label: 'Good', color: 'text-green-600 dark:text-green-400', bg: 'bg-green-50 dark:bg-green-900/20' };
    }
  };

  // Format time ago
  const formatTimeAgo = (date: Date): string => {
    const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000);
    if (seconds < 60) return 'Just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hr ago`;
    return `${Math.floor(seconds / 86400)} days ago`;
  };

  // Handle Run Scan button
  const handleRunScan = async () => {
    setIsScanning(true);
    try {
      // Refresh all monitoring data
      await Promise.all([
        fetchThreatStats(),
        fetchSystemMetrics(),
        fetchRecentThreats()
      ]);
      setLastScanTime(new Date());
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      setIsScanning(false);
    }
  };

  // Handle View Alerts button
  const handleViewAlerts = async () => {
    try {
      const alerts = await invoke('get_all_alerts');
      console.log('All alerts:', alerts);
      // TODO: Navigate to alerts view or show modal
      alert(`Found ${recentThreats.length} threats. Alerts view coming soon!`);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
    }
  };

  // Handle System Health button
  const handleSystemHealth = () => {
    if (systemMetrics) {
      const healthInfo = `
CPU Usage: ${systemMetrics.cpu.usage_percent.toFixed(1)}%
Memory Usage: ${systemMetrics.memory.usage_percent.toFixed(1)}%
System Health: ${getSystemHealthStatus().label}
      `.trim();
      alert(healthInfo);
    }
  };

  // Handle Generate Report button
  const handleGenerateReport = () => {
    const reportData = {
      securityScore: calculateSecurityScore(),
      activeThreats: threatStats?.total_threats || 0,
      systemHealth: getSystemHealthStatus().label,
      lastScan: lastScanTime.toISOString(),
      threatBreakdown: threatStats?.by_severity || {},
      timestamp: new Date().toISOString()
    };
    console.log('Report Data:', reportData);
    alert('Report generated! Check console for details. Full report export coming soon!');
  };

  const securityScore = calculateSecurityScore();
  const activeThreats = threatStats?.total_threats || 0;
  const systemHealth = getSystemHealthStatus();

  const stats = [
    {
      label: 'Security Score',
      value: `${securityScore}%`,
      icon: Shield,
      color: securityScore >= 80 ? 'text-green-600 dark:text-green-400' : securityScore >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400',
      bg: securityScore >= 80 ? 'bg-green-50 dark:bg-green-900/20' : securityScore >= 60 ? 'bg-yellow-50 dark:bg-yellow-900/20' : 'bg-red-50 dark:bg-red-900/20'
    },
    {
      label: 'Active Threats',
      value: activeThreats.toString(),
      icon: AlertTriangle,
      color: activeThreats === 0 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400',
      bg: activeThreats === 0 ? 'bg-green-50 dark:bg-green-900/20' : 'bg-red-50 dark:bg-red-900/20'
    },
    {
      label: 'System Health',
      value: systemHealth.label,
      icon: Activity,
      color: systemHealth.color,
      bg: systemHealth.bg
    },
    {
      label: 'Last Scan',
      value: formatTimeAgo(lastScanTime),
      icon: CheckCircle2,
      color: 'text-gray-600 dark:text-gray-400',
      bg: 'bg-gray-50 dark:bg-gray-900/20'
    },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">Security Dashboard</h2>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Real-time overview of your system's security posture
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div
              key={index}
              className="bg-white dark:bg-gray-800 p-6 rounded-xl border border-gray-200 dark:border-gray-700 hover:shadow-lg transition-shadow"
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">{stat.label}</p>
                  <p className="text-2xl font-bold mt-2 text-gray-900 dark:text-gray-100">{stat.value}</p>
                </div>
                <div className={`${stat.bg} p-3 rounded-lg`}>
                  <Icon className={`w-6 h-6 ${stat.color}`} />
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Quick Actions */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <button
            onClick={handleRunScan}
            disabled={isScanning}
            className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {isScanning ? (
              <RefreshCw className="w-6 h-6 text-blue-600 dark:text-blue-400 mx-auto mb-2 animate-spin" />
            ) : (
              <Shield className="w-6 h-6 text-blue-600 dark:text-blue-400 mx-auto mb-2" />
            )}
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {isScanning ? 'Scanning...' : 'Run Scan'}
            </p>
          </button>
          <button
            onClick={handleSystemHealth}
            className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <Activity className="w-6 h-6 text-blue-600 dark:text-blue-400 mx-auto mb-2" />
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">System Health</p>
          </button>
          <button
            onClick={handleViewAlerts}
            className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <AlertTriangle className="w-6 h-6 text-blue-600 dark:text-blue-400 mx-auto mb-2" />
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">View Alerts</p>
          </button>
          <button
            onClick={handleGenerateReport}
            className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
          >
            <CheckCircle2 className="w-6 h-6 text-blue-600 dark:text-blue-400 mx-auto mb-2" />
            <p className="text-sm font-medium text-gray-900 dark:text-gray-100">Generate Report</p>
          </button>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Recent Threats</h3>
        <div className="space-y-4">
          {recentThreats.length > 0 ? (
            recentThreats.map((threat) => {
              const severityColor =
                threat.severity === 'Critical'
                  ? 'bg-red-500'
                  : threat.severity === 'High'
                  ? 'bg-orange-500'
                  : threat.severity === 'Medium'
                  ? 'bg-yellow-500'
                  : 'bg-blue-500';

              const severityBg =
                threat.severity === 'Critical'
                  ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
                  : threat.severity === 'High'
                  ? 'bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-400'
                  : threat.severity === 'Medium'
                  ? 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400'
                  : 'bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400';

              const timeAgo = formatTimeAgo(new Date(threat.timestamp));

              return (
                <div
                  key={threat.id}
                  className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                >
                  <div className="flex items-center space-x-3">
                    <div className={`w-2 h-2 ${severityColor} rounded-full`}></div>
                    <div className="max-w-md">
                      <p className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                        {threat.title}
                      </p>
                      <p className="text-xs text-gray-500 dark:text-gray-400">{timeAgo}</p>
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded whitespace-nowrap ${severityBg}`}>
                    {threat.severity}
                  </span>
                </div>
              );
            })
          ) : (
            <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
              <div className="flex items-center space-x-3">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <div>
                  <p className="text-sm font-medium text-gray-900 dark:text-gray-100">
                    No threats detected
                  </p>
                  <p className="text-xs text-gray-500 dark:text-gray-400">System is secure</p>
                </div>
              </div>
              <span className="text-xs px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 rounded">
                All Clear
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
