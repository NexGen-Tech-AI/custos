// Network Security Section - EDR for Traffic
// Main container with tab navigation between sub-views

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Activity, Network, Search, Settings } from 'lucide-react';
import { invoke } from '@tauri-apps/api/core';
import { ConnectionStats } from '@/types';

import NetworkOverview from './NetworkOverview';
import SignalsFeed from './SignalsFeed';
import SegmentsTopology from './SegmentsTopology';
import ConnectionExplorer from './ConnectionExplorer';
import ResponseControls from './ResponseControls';

type TabName = 'overview' | 'signals' | 'segments' | 'explorer' | 'controls';

interface Tab {
  id: TabName;
  name: string;
  icon: React.ComponentType<{ className?: string }>;
}

const tabs: Tab[] = [
  { id: 'overview', name: 'Overview', icon: Activity },
  { id: 'signals', name: 'Live Signals', icon: Network },
  { id: 'segments', name: 'Segments & Topology', icon: Shield },
  { id: 'explorer', name: 'Connection Explorer', icon: Search },
  { id: 'controls', name: 'Response Controls', icon: Settings },
];

const NetworkSecuritySection: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabName>('overview');
  const [stats, setStats] = useState<ConnectionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  // Load connection statistics
  const loadStats = async () => {
    try {
      const result = await invoke<ConnectionStats>('get_connection_stats', {
        hours: 24,
      });
      setStats(result);
      setLastUpdate(new Date());
    } catch (error) {
      console.error('Failed to load connection stats:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();

    // Auto-refresh every 10 seconds
    const interval = setInterval(loadStats, 10000);

    return () => clearInterval(interval);
  }, []);

  const renderTabContent = () => {
    switch (activeTab) {
      case 'overview':
        return <NetworkOverview stats={stats} />;
      case 'signals':
        return <SignalsFeed />;
      case 'segments':
        return <SegmentsTopology />;
      case 'explorer':
        return <ConnectionExplorer />;
      case 'controls':
        return <ResponseControls />;
      default:
        return <NetworkOverview stats={stats} />;
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
        <div className="text-xl font-semibold text-white">Network Security</div>

        <div className="flex items-center gap-2 text-xs text-gray-400">
          <Activity className="h-3 w-3" />
          <span>Last updated: {lastUpdate.toLocaleTimeString()}</span>
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
            label="Total Connections"
            value={stats.total_connections.toLocaleString()}
            icon={Network}
            color="blue"
          />
          <StatCard
            label="Unique Processes"
            value={stats.unique_processes.toLocaleString()}
            icon={Activity}
            color="green"
          />
          <StatCard
            label="Destinations"
            value={stats.unique_destinations.toLocaleString()}
            icon={Shield}
            color="purple"
          />
          <StatCard
            label="Suspicious"
            value={stats.suspicious_connections.toLocaleString()}
            icon={Shield}
            color={stats.suspicious_connections > 0 ? 'red' : 'gray'}
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
            <div className="text-gray-400">Loading network data...</div>
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
  color: 'blue' | 'green' | 'purple' | 'red' | 'gray';
}

const StatCard: React.FC<StatCardProps> = ({ label, value, icon: Icon, color }) => {
  const colorClasses = {
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    green: 'bg-green-500/10 text-green-400 border-green-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
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

export default NetworkSecuritySection;
