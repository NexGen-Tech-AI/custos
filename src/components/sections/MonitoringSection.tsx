import React from 'react';
import { Dashboard } from '../Dashboard';
import { SystemInfo, SystemMetrics } from '../../types';

interface MonitoringSectionProps {
  systemInfo: SystemInfo | null;
  metrics: SystemMetrics | null;
}

export const MonitoringSection: React.FC<MonitoringSectionProps> = ({ systemInfo, metrics }) => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">System Monitoring</h2>
        <p className="text-gray-600 dark:text-gray-400 mt-2">
          Real-time system performance metrics and resource utilization
        </p>
      </div>
      <Dashboard systemInfo={systemInfo} metrics={metrics} />
    </div>
  );
};
