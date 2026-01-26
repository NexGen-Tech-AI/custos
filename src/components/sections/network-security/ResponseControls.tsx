// Response Controls - Network isolation and containment actions

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Shield, Lock, Ban, RotateCcw, AlertTriangle } from 'lucide-react';
import { IsolationRecord } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

const ResponseControls: React.FC = () => {
  const [isolationHistory, setIsolationHistory] = useState<IsolationRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadIsolationHistory();
  }, []);

  const loadIsolationHistory = async () => {
    try {
      const result = await invoke<IsolationRecord[]>('get_isolation_history');
      setIsolationHistory(result);
    } catch (error) {
      console.error('Failed to load isolation history:', error);
    } finally {
      setLoading(false);
    }
  };

  const activeIsolations = isolationHistory.filter((r) => r.status === 'Active');

  return (
    <div className="space-y-6">
      {/* Active Isolations */}
      <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Lock className="h-5 w-5 text-red-400" />
            <h3 className="text-lg font-semibold text-white">Active Isolations</h3>
          </div>
          <Badge className="rounded-full bg-red-500/20 text-red-300">
            {activeIsolations.length} Active
          </Badge>
        </div>

        {activeIsolations.length === 0 ? (
          <div className="py-8 text-center text-gray-400">
            <Shield className="mx-auto h-12 w-12 text-gray-600" />
            <p className="mt-4">No active isolations</p>
            <p className="mt-1 text-sm text-gray-500">
              Network is operating normally
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeIsolations.map((record) => (
              <IsolationCard key={record.id} record={record} onRollback={loadIsolationHistory} />
            ))}
          </div>
        )}
      </div>

      {/* Quick Actions */}
      <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
        <div className="mb-4 flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-yellow-400" />
          <h3 className="text-lg font-semibold text-white">Quick Actions</h3>
        </div>

        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <ActionButton
            icon={Ban}
            title="Block IP Address"
            description="Temporarily block a destination IP"
            onClick={() => console.log('Block IP')}
          />
          <ActionButton
            icon={Lock}
            title="Isolate Host"
            description="Completely isolate a device from network"
            onClick={() => console.log('Isolate host')}
          />
          <ActionButton
            icon={Shield}
            title="Block Port"
            description="Block traffic on a specific port"
            onClick={() => console.log('Block port')}
          />
          <ActionButton
            icon={Ban}
            title="Block ASN"
            description="Block all IPs from an ASN"
            onClick={() => console.log('Block ASN')}
          />
        </div>
      </div>

      {/* Isolation History */}
      <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
        <div className="mb-4 flex items-center gap-2">
          <RotateCcw className="h-5 w-5 text-monitor-400" />
          <h3 className="text-lg font-semibold text-white">Isolation History</h3>
        </div>

        {loading ? (
          <div className="py-8 text-center text-gray-400">Loading history...</div>
        ) : isolationHistory.length === 0 ? (
          <div className="py-8 text-center text-gray-400">No isolation actions yet</div>
        ) : (
          <div className="space-y-2">
            {isolationHistory.slice(0, 10).map((record) => (
              <HistoryCard key={record.id} record={record} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

interface IsolationCardProps {
  record: IsolationRecord;
  onRollback: () => void;
}

const IsolationCard: React.FC<IsolationCardProps> = ({ record, onRollback }) => {
  const [rollingBack, setRollingBack] = useState(false);

  const handleRollback = async () => {
    setRollingBack(true);
    try {
      await invoke('rollback_isolation', { actionId: record.id });
      onRollback();
    } catch (error) {
      console.error('Failed to rollback:', error);
    } finally {
      setRollingBack(false);
    }
  };

  const getActionDescription = (action: any): string => {
    if ('BlockDestination' in action) {
      return `Blocked IP: ${action.BlockDestination.ip}`;
    }
    if ('TemporaryIsolate' in action) {
      return `Isolated host: ${action.TemporaryIsolate.hostname}`;
    }
    if ('BlockPort' in action) {
      return `Blocked port: ${action.BlockPort.port}/${action.BlockPort.protocol}`;
    }
    return 'Unknown action';
  };

  return (
    <div className="flex items-center justify-between rounded-xl border border-red-700/50 bg-red-500/10 p-4">
      <div>
        <div className="font-medium text-white">{getActionDescription(record.action)}</div>
        <div className="mt-1 text-xs text-gray-400">
          By {record.executed_by} • {new Date(record.executed_at).toLocaleString()}
          {record.expires_at && ` • Expires ${new Date(record.expires_at).toLocaleString()}`}
        </div>
      </div>

      <Button
        size="sm"
        variant="outline"
        onClick={handleRollback}
        disabled={rollingBack}
        className="rounded-lg border-gray-600 text-gray-300 hover:bg-gray-700"
      >
        <RotateCcw className="mr-2 h-4 w-4" />
        Rollback
      </Button>
    </div>
  );
};

interface HistoryCardProps {
  record: IsolationRecord;
}

const HistoryCard: React.FC<HistoryCardProps> = ({ record }) => {
  const statusColors = {
    Active: 'bg-green-500/20 text-green-300 border-green-500/30',
    Expired: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
    RolledBack: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  };

  return (
    <div className="flex items-center justify-between rounded-lg border border-gray-700/50 bg-gray-800/20 p-3">
      <div className="text-sm text-gray-300">
        {new Date(record.executed_at).toLocaleString()} • {record.executed_by}
      </div>
      <Badge className={`rounded-full text-xs ${statusColors[record.status]}`}>
        {record.status}
      </Badge>
    </div>
  );
};

interface ActionButtonProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  onClick: () => void;
}

const ActionButton: React.FC<ActionButtonProps> = ({ icon: Icon, title, description, onClick }) => {
  return (
    <button
      onClick={onClick}
      className="group rounded-xl border border-gray-700 bg-gray-800/30 p-4 text-left transition-all hover:border-monitor-500 hover:bg-gray-800"
    >
      <div className="flex items-start gap-3">
        <div className="rounded-lg bg-monitor-600/20 p-2">
          <Icon className="h-5 w-5 text-monitor-400" />
        </div>
        <div>
          <div className="font-medium text-white">{title}</div>
          <div className="mt-1 text-xs text-gray-400">{description}</div>
        </div>
      </div>
    </button>
  );
};

export default ResponseControls;
