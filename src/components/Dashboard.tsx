import React from 'react';
import { SystemInfo, SystemMetrics } from '../types';
import { DraggableDashboard } from './DraggableDashboard';

interface DashboardProps {
  systemInfo: SystemInfo | null;
  metrics: SystemMetrics | null;
}

export const Dashboard: React.FC<DashboardProps> = ({ systemInfo, metrics }) => {
  return <DraggableDashboard systemInfo={systemInfo} metrics={metrics} />;
};