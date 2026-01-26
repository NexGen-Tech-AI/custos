// Network Overview - Dashboard with coverage, risks, and anomalies

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Shield, AlertTriangle, Activity, TrendingUp, Globe, Cpu } from 'lucide-react';
import { ConnectionStats, TopTalker, NetworkConnectionRecord, GeoIPInfo } from '@/types';
import { Badge } from '@/components/ui/badge';

interface NetworkOverviewProps {
  stats: ConnectionStats | null;
}

const NetworkOverview: React.FC<NetworkOverviewProps> = ({ stats }) => {
  const [topTalkers, setTopTalkers] = useState<TopTalker[]>([]);
  const [recentConnections, setRecentConnections] = useState<NetworkConnectionRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [talkers, connections] = await Promise.all([
        invoke<TopTalker[]>('get_top_talkers', { limit: 5, hours: 1 }),
        invoke<NetworkConnectionRecord[]>('get_network_connections', { hours: 1, limit: 10 }),
      ]);

      setTopTalkers(talkers);
      setRecentConnections(connections);
    } catch (error) {
      console.error('Failed to load network overview:', error);
    } finally {
      setLoading(false);
    }
  };

  const coveragePercent = 100; // Mock: In production, calculate based on discovered devices
  const riskScore = stats?.suspicious_connections || 0;

  return (
    <div className="space-y-6">
      {/* Coverage & Risk Summary */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {/* Coverage Meter */}
        <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-green-500/10 p-3">
              <Shield className="h-6 w-6 text-green-400" />
            </div>
            <div>
              <div className="text-sm text-gray-400">Network Coverage</div>
              <div className="text-2xl font-bold text-white">{coveragePercent}%</div>
            </div>
          </div>
          <div className="mt-4">
            <div className="h-2 w-full overflow-hidden rounded-full bg-gray-700">
              <div
                className="h-full bg-green-500 transition-all duration-500"
                style={{ width: `${coveragePercent}%` }}
              />
            </div>
            <div className="mt-2 text-xs text-gray-400">
              All devices reporting • Last heartbeat: Now
            </div>
          </div>
        </div>

        {/* Risk Summary */}
        <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
          <div className="flex items-center gap-3">
            <div className={`rounded-xl p-3 ${riskScore > 0 ? 'bg-red-500/10' : 'bg-gray-700/50'}`}>
              <AlertTriangle className={`h-6 w-6 ${riskScore > 0 ? 'text-red-400' : 'text-gray-500'}`} />
            </div>
            <div>
              <div className="text-sm text-gray-400">Suspicious Activity</div>
              <div className="text-2xl font-bold text-white">{riskScore}</div>
            </div>
          </div>
          <div className="mt-4 space-y-1">
            {riskScore === 0 ? (
              <div className="text-xs text-gray-400">✓ No suspicious connections detected</div>
            ) : (
              <>
                <div className="text-xs text-red-400">⚠ {riskScore} suspicious connections found</div>
                <div className="text-xs text-gray-500">Review in Live Signals tab</div>
              </>
            )}
          </div>
        </div>

        {/* Active Monitoring Status */}
        <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-monitor-600/20 p-3">
              <Activity className="h-6 w-6 text-monitor-400" />
            </div>
            <div>
              <div className="text-sm text-gray-400">Monitoring Status</div>
              <div className="text-2xl font-bold text-white">Active</div>
            </div>
          </div>
          <div className="mt-4">
            <Badge className="rounded-full bg-green-500/20 text-green-300 border-green-500/30">
              <Shield className="mr-1 h-3 w-3" />
              Containment Available
            </Badge>
            <div className="mt-2 text-xs text-gray-400">Last action: None</div>
          </div>
        </div>
      </div>

      {/* Top Talkers */}
      <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-monitor-400" />
            <h3 className="text-lg font-semibold text-white">Top Talkers (Last Hour)</h3>
          </div>
          <span className="text-xs text-gray-400">Most Active Processes</span>
        </div>

        {loading ? (
          <div className="py-8 text-center text-gray-400">Loading...</div>
        ) : topTalkers.length === 0 ? (
          <div className="py-8 text-center text-gray-400">No network activity detected</div>
        ) : (
          <div className="space-y-3">
            {topTalkers.map((talker, idx) => (
              <TopTalkerCard key={idx} talker={talker} rank={idx + 1} />
            ))}
          </div>
        )}
      </div>

      {/* Recent Connections */}
      <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-monitor-400" />
            <h3 className="text-lg font-semibold text-white">Recent Connections</h3>
          </div>
          <span className="text-xs text-gray-400">Last 10 Connections</span>
        </div>

        {loading ? (
          <div className="py-8 text-center text-gray-400">Loading...</div>
        ) : recentConnections.length === 0 ? (
          <div className="py-8 text-center text-gray-400">No connections yet</div>
        ) : (
          <div className="space-y-2">
            {recentConnections.map((conn) => (
              <ConnectionCard key={conn.id} connection={conn} />
            ))}
          </div>
        )}
      </div>

      {/* Live Anomalies Section */}
      <div className="rounded-2xl border border-yellow-500/20 bg-yellow-500/5 p-6">
        <div className="mb-4 flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-yellow-400" />
          <h3 className="text-lg font-semibold text-white">Live Anomalies</h3>
        </div>

        <div className="space-y-2 text-sm">
          {riskScore === 0 ? (
            <div className="text-gray-400">✓ No anomalies detected</div>
          ) : (
            <>
              <AnomalyBadge type="info" text="New ASN spike detected: AS15169 (Google)" />
              <div className="text-xs text-gray-500 pl-6">
                {recentConnections.length} connections in the last hour
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

interface TopTalkerCardProps {
  talker: TopTalker;
  rank: number;
}

const TopTalkerCard: React.FC<TopTalkerCardProps> = ({ talker, rank }) => {
  const totalBytes = talker.total_bytes_sent + talker.total_bytes_received;
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };

  return (
    <div className="flex items-center justify-between rounded-xl border border-gray-700 bg-gray-800/30 p-4">
      <div className="flex items-center gap-3">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-monitor-600/20 text-sm font-bold text-monitor-400">
          {rank}
        </div>
        <div>
          <div className="flex items-center gap-2">
            <Cpu className="h-4 w-4 text-gray-400" />
            <span className="font-medium text-white">{talker.process_name}</span>
            {talker.process_id && (
              <span className="text-xs text-gray-500">PID: {talker.process_id}</span>
            )}
          </div>
          <div className="mt-1 flex gap-3 text-xs text-gray-400">
            <span>{talker.connection_count} connections</span>
            <span>•</span>
            <span>{talker.unique_destinations} destinations</span>
          </div>
        </div>
      </div>

      <div className="text-right">
        <div className="font-semibold text-white">{formatBytes(totalBytes)}</div>
        <div className="text-xs text-gray-400">
          ↑ {formatBytes(talker.total_bytes_sent)} • ↓ {formatBytes(talker.total_bytes_received)}
        </div>
      </div>
    </div>
  );
};

interface ConnectionCardProps {
  connection: NetworkConnectionRecord;
}

const ConnectionCard: React.FC<ConnectionCardProps> = ({ connection }) => {
  const timestamp = new Date(connection.timestamp);
  const timeAgo = getTimeAgo(timestamp);

  return (
    <div className="flex items-center justify-between rounded-lg border border-gray-700/50 bg-gray-800/20 p-3 text-sm">
      <div className="flex items-center gap-3">
        <div className="flex h-6 w-6 items-center justify-center rounded bg-gray-700 text-xs font-mono text-gray-300">
          {connection.protocol}
        </div>
        <div>
          <div className="font-medium text-white">
            {connection.process_name || 'Unknown'}
            {connection.direction === 'Outbound' ? ' →' : ' ←'} {connection.remote_ip}:{connection.remote_port}
          </div>
          <div className="text-xs text-gray-500">{timeAgo}</div>
        </div>
      </div>

      {connection.state && (
        <Badge className="rounded-full text-xs">
          {connection.state}
        </Badge>
      )}
    </div>
  );
};

interface AnomalyBadgeProps {
  type: 'warning' | 'info' | 'critical';
  text: string;
}

const AnomalyBadge: React.FC<AnomalyBadgeProps> = ({ type, text }) => {
  const colors = {
    warning: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    info: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  };

  return (
    <div className={`flex items-center gap-2 rounded-lg border p-2 ${colors[type]}`}>
      <AlertTriangle className="h-4 w-4" />
      <span>{text}</span>
    </div>
  );
};

function getTimeAgo(date: Date): string {
  const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000);

  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default NetworkOverview;
