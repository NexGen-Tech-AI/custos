// Vulnerabilities Section - Advanced vulnerability scanner and management
// Main container with tab navigation

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Package, Settings, Activity } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import { ScanStatistics } from '@/types';

import PostureOverview from './PostureOverview';
import FindingsList from './FindingsList';
import RemediationPanel from './RemediationPanel';
import ScanningProgress from './ScanningProgress';

type TabName = 'overview' | 'scan' | 'findings' | 'remediation';

interface Tab {
  id: TabName;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
}

const tabs: Tab[] = [
  { id: 'overview', name: 'Posture Overview', icon: Shield },
  { id: 'scan', name: 'Scan System', icon: Activity },
  { id: 'findings', name: 'Findings', icon: AlertTriangle },
  { id: 'remediation', name: 'Remediation', icon: Settings },
];

const VulnerabilitiesSection: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabName>('overview');
  const [stats, setStats] = useState<ScanStatistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastScan, setLastScan] = useState<Date>(new Date());
  const [scanning, setScanning] = useState(false);

  // Load vulnerability statistics
  const loadStats = async () => {
    try {
      const result = await invoke<ScanStatistics>('get_vulnerability_statistics');
      setStats(result);
      setLastScan(new Date());
    } catch (error) {
      console.error('Failed to load vulnerability statistics:', error);
    } finally {
      setLoading(false);
    }
  };

  // Trigger a fresh scan
  const runScan = async () => {
    setScanning(true);
    try {
      await invoke('scan_vulnerabilities');
      await loadStats();
    } catch (error) {
      console.error('Failed to run vulnerability scan:', error);
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => {
    loadStats();

    // Auto-refresh stats every 30 seconds
    const interval = setInterval(loadStats, 30000);

    return () => clearInterval(interval);
  }, []);

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return <PostureOverview stats={stats} onRescan={runScan} />;
      case 'scan':
        return <ScanningProgress onScanComplete={loadStats} />;
      case 'findings':
        return <FindingsList />;
      case 'remediation':
        return <RemediationPanel />;
      default:
        return <PostureOverview stats={stats} onRescan={runScan} />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35 }}
        className="flex items-center justify-between"
      >
        <div className="text-xl font-semibold text-white">Vulnerability Scanner</div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <Activity className="h-3 w-3" />
            <span>Last scan: {lastScan.toLocaleTimeString()}</span>
          </div>

          <button
            onClick={runScan}
            disabled={scanning}
            className="rounded-xl bg-monitor-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-monitor-700 disabled:opacity-50"
          >
            {scanning ? 'Scanning...' : 'Scan Now'}
          </button>
        </div>
      </motion.div>

      {/* Stats Summary Bar */}
      {stats && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: 0.1 }}
          className="grid grid-cols-2 gap-3 md:grid-cols-4"
        >
          <StatCard
            label="Total Vulnerabilities"
            value={stats.total_vulnerabilities.toLocaleString()}
            icon={Package}
            color={stats.total_vulnerabilities > 0 ? 'red' : 'gray'}
          />
          <StatCard
            label="Critical + High"
            value={(stats.critical + stats.high).toLocaleString()}
            icon={AlertTriangle}
            color={stats.critical + stats.high > 0 ? 'red' : 'gray'}
          />
          <StatCard
            label="Exploitable"
            value={stats.exploitable.toLocaleString()}
            icon={Shield}
            color={stats.exploitable > 0 ? 'orange' : 'gray'}
          />
          <StatCard
            label="Fix Available"
            value={stats.fix_available.toLocaleString()}
            icon={Settings}
            color={stats.fix_available > 0 ? 'green' : 'gray'}
          />
        </motion.div>
      )}

      {/* Tab Navigation */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.35, delay: 0.2 }}
        className="border-b border-gray-700"
      >
        <nav className="-mb-px flex space-x-4" aria-label="Tabs">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`
                  group inline-flex items-center gap-2 border-b-2 px-3 py-3 text-sm font-medium transition-colors
                  ${
                    isActive
                      ? 'border-monitor-500 text-monitor-400'
                      : 'border-transparent text-gray-400 hover:border-gray-600 hover:text-gray-300'
                  }
                `}
              >
                <Icon className="h-4 w-4" />
                {tab.name}
              </button>
            );
          })}
        </nav>
      </motion.div>

      {/* Tab Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        {loading && activeTab === 'overview' ? (
          <div className="flex items-center justify-center py-12">
            <div className="text-gray-400">Loading vulnerability data...</div>
          </div>
        ) : (
          renderTabContent()
        )}
      </motion.div>
    </div>
  );
};

interface StatCardProps {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  color: 'red' | 'orange' | 'green' | 'gray';
}

const StatCard: React.FC<StatCardProps> = ({ label, value, icon: Icon, color }) => {
  const colorClasses = {
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
    orange: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    green: 'bg-green-500/10 text-green-400 border-green-500/20',
    gray: 'bg-gray-500/10 text-gray-400 border-gray-500/20',
  };

  return (
    <div className={`rounded-2xl border p-4 ${colorClasses[color]}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="text-xs text-gray-400">{label}</div>
          <div className="mt-1 text-2xl font-bold">{value}</div>
        </div>
        <Icon className="h-8 w-8 opacity-50" />
      </div>
    </div>
  );
};

export default VulnerabilitiesSection;
