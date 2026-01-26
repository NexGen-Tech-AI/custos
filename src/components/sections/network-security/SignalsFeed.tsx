// Signals Feed - Live connection feed with threat indicators and action buttons

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Shield, AlertTriangle, Eye, Ban, Lock, Search,
  Globe, MapPin, Server, Filter
} from 'lucide-react';
import { NetworkConnectionRecord, GeoIPInfo, NetworkSegment } from '@/types';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';

const SignalsFeed: React.FC = () => {
  const [connections, setConnections] = useState<NetworkConnectionRecord[]>([]);
  const [selectedConnection, setSelectedConnection] = useState<NetworkConnectionRecord | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSuspicious, setFilterSuspicious] = useState(false);

  useEffect(() => {
    loadConnections();

    // Auto-refresh every 5 seconds
    const interval = setInterval(loadConnections, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadConnections = async () => {
    try {
      const result = await invoke<NetworkConnectionRecord[]>('get_network_connections', {
        hours: 1,
        limit: 100,
      });
      setConnections(result);
    } catch (error) {
      console.error('Failed to load connections:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredConnections = connections.filter((conn) => {
    if (searchQuery && !conn.process_name?.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !conn.remote_ip.includes(searchQuery)) {
      return false;
    }
    // TODO: Add suspicious connection filtering when backend supports it
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="flex items-center justify-between gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search by process name or IP..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-xl border border-gray-700 bg-gray-800 py-2 pl-10 pr-4 text-sm text-white placeholder-gray-400 focus:border-monitor-500 focus:outline-none focus:ring-1 focus:ring-monitor-500"
          />
        </div>

        <Button
          onClick={() => setFilterSuspicious(!filterSuspicious)}
          className={`rounded-xl ${filterSuspicious ? 'bg-red-500/20 text-red-300 hover:bg-red-500/30' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
        >
          <Filter className="mr-2 h-4 w-4" />
          Suspicious Only
        </Button>

        <Button onClick={loadConnections} className="rounded-xl bg-monitor-600 text-white hover:bg-monitor-700">
          <Shield className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* Connection Feed */}
      <div className="space-y-2">
        {loading ? (
          <div className="py-12 text-center text-gray-400">Loading connections...</div>
        ) : filteredConnections.length === 0 ? (
          <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-12 text-center">
            <Globe className="mx-auto h-12 w-12 text-gray-600" />
            <p className="mt-4 text-gray-400">No connections found</p>
            <p className="mt-1 text-sm text-gray-500">
              {searchQuery ? 'Try a different search query' : 'Start using the network to see connections'}
            </p>
          </div>
        ) : (
          filteredConnections.map((conn) => (
            <SignalRow
              key={conn.id}
              connection={conn}
              onClick={() => setSelectedConnection(conn)}
              isSelected={selectedConnection?.id === conn.id}
            />
          ))
        )}
      </div>

      {/* Connection Details Panel */}
      {selectedConnection && (
        <ConnectionDetailsPanel
          connection={selectedConnection}
          onClose={() => setSelectedConnection(null)}
        />
      )}
    </div>
  );
};

interface SignalRowProps {
  connection: NetworkConnectionRecord;
  onClick: () => void;
  isSelected: boolean;
}

const SignalRow: React.FC<SignalRowProps> = ({ connection, onClick, isSelected }) => {
  const [geoInfo, setGeoInfo] = useState<GeoIPInfo | null>(null);
  const [segment, setSegment] = useState<NetworkSegment | null>(null);

  useEffect(() => {
    // Load GeoIP info
    invoke<GeoIPInfo>('lookup_ip_info', { ip: connection.remote_ip })
      .then(setGeoInfo)
      .catch(console.error);

    // Classify IP
    invoke<NetworkSegment>('classify_ip', { ip: connection.remote_ip })
      .then(setSegment)
      .catch(console.error);
  }, [connection.remote_ip]);

  const timestamp = new Date(connection.timestamp);
  const isSuspicious = geoInfo?.is_tor || geoInfo?.is_known_vpn;

  return (
    <div
      onClick={onClick}
      className={`
        group cursor-pointer rounded-xl border p-4 transition-all
        ${isSelected
          ? 'border-monitor-500 bg-monitor-500/10'
          : 'border-gray-700 bg-gray-800/50 hover:border-gray-600 hover:bg-gray-800'
        }
      `}
    >
      <div className="flex items-center justify-between">
        {/* Left: Process + Connection Info */}
        <div className="flex items-center gap-4">
          {/* Severity Badge */}
          <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${
            isSuspicious ? 'bg-red-500/20' : 'bg-gray-700'
          }`}>
            {isSuspicious ? (
              <AlertTriangle className="h-5 w-5 text-red-400" />
            ) : (
              <Shield className="h-5 w-5 text-gray-400" />
            )}
          </div>

          {/* Connection Details */}
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-medium text-white">{connection.process_name || 'Unknown Process'}</span>
              {connection.process_id && (
                <span className="text-xs text-gray-500">PID: {connection.process_id}</span>
              )}
              <span className="text-gray-500">→</span>
              <span className="font-mono text-sm text-monitor-400">{connection.remote_ip}:{connection.remote_port}</span>
            </div>

            <div className="flex items-center gap-3 text-xs">
              <span className="text-gray-500">{timestamp.toLocaleTimeString()}</span>
              <span className="text-gray-600">•</span>
              <Badge className="rounded-full text-xs">{connection.protocol}</Badge>
              {segment && segment !== 'Unknown' && (
                <>
                  <span className="text-gray-600">•</span>
                  <Badge className="rounded-full text-xs" variant="outline">
                    {segment}
                  </Badge>
                </>
              )}
              {geoInfo?.country_code && (
                <>
                  <span className="text-gray-600">•</span>
                  <div className="flex items-center gap-1 text-gray-400">
                    <MapPin className="h-3 w-3" />
                    {geoInfo.country_code}
                  </div>
                </>
              )}
              {geoInfo?.asn_org && (
                <>
                  <span className="text-gray-600">•</span>
                  <div className="flex items-center gap-1 text-gray-400">
                    <Server className="h-3 w-3" />
                    AS{geoInfo.asn} ({geoInfo.asn_org})
                  </div>
                </>
              )}
            </div>

            {/* Suspicion Reasons */}
            {isSuspicious && (
              <div className="mt-2 flex items-center gap-2 text-xs text-red-400">
                <AlertTriangle className="h-3 w-3" />
                <span>
                  {geoInfo?.is_tor && 'Tor exit node'}
                  {geoInfo?.is_tor && geoInfo?.is_known_vpn && ' • '}
                  {geoInfo?.is_known_vpn && 'VPN/Proxy detected'}
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Right: Action Buttons */}
        <div className="flex items-center gap-2 opacity-0 transition-opacity group-hover:opacity-100">
          <Button
            size="sm"
            variant="outline"
            className="rounded-lg border-gray-600 text-gray-300 hover:bg-gray-700"
            onClick={(e) => {
              e.stopPropagation();
              // TODO: Allow connection
            }}
          >
            <Eye className="h-4 w-4" />
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="rounded-lg border-red-600 text-red-400 hover:bg-red-500/20"
            onClick={(e) => {
              e.stopPropagation();
              // TODO: Block destination
            }}
          >
            <Ban className="h-4 w-4" />
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="rounded-lg border-yellow-600 text-yellow-400 hover:bg-yellow-500/20"
            onClick={(e) => {
              e.stopPropagation();
              // TODO: Investigate
            }}
          >
            <Search className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  );
};

interface ConnectionDetailsPanelProps {
  connection: NetworkConnectionRecord;
  onClose: () => void;
}

const ConnectionDetailsPanel: React.FC<ConnectionDetailsPanelProps> = ({ connection, onClose }) => {
  const [geoInfo, setGeoInfo] = useState<GeoIPInfo | null>(null);

  useEffect(() => {
    invoke<GeoIPInfo>('lookup_ip_info', { ip: connection.remote_ip })
      .then(setGeoInfo)
      .catch(console.error);
  }, [connection.remote_ip]);

  return (
    <div className="fixed inset-y-0 right-0 w-96 border-l border-gray-700 bg-gray-900 p-6 shadow-2xl">
      <div className="mb-6 flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Connection Details</h3>
        <Button
          size="sm"
          variant="ghost"
          onClick={onClose}
          className="text-gray-400 hover:text-white"
        >
          ✕
        </Button>
      </div>

      <div className="space-y-6">
        {/* Process Info */}
        <div>
          <h4 className="mb-2 text-sm font-medium text-gray-400">Process</h4>
          <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-4">
            <div className="font-medium text-white">{connection.process_name || 'Unknown'}</div>
            {connection.process_id && (
              <div className="mt-1 text-sm text-gray-400">PID: {connection.process_id}</div>
            )}
          </div>
        </div>

        {/* Destination Info */}
        <div>
          <h4 className="mb-2 text-sm font-medium text-gray-400">Destination</h4>
          <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-4 space-y-2">
            <div className="font-mono text-white">{connection.remote_ip}:{connection.remote_port}</div>
            {geoInfo && (
              <>
                {geoInfo.country_name && (
                  <div className="flex items-center gap-2 text-sm text-gray-400">
                    <MapPin className="h-4 w-4" />
                    {geoInfo.country_name}
                  </div>
                )}
                {geoInfo.asn_org && (
                  <div className="flex items-center gap-2 text-sm text-gray-400">
                    <Server className="h-4 w-4" />
                    AS{geoInfo.asn} • {geoInfo.asn_org}
                  </div>
                )}
              </>
            )}
          </div>
        </div>

        {/* Protocol & State */}
        <div>
          <h4 className="mb-2 text-sm font-medium text-gray-400">Connection</h4>
          <div className="rounded-xl border border-gray-700 bg-gray-800/50 p-4 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-400">Protocol</span>
              <span className="text-white">{connection.protocol}</span>
            </div>
            {connection.state && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">State</span>
                <span className="text-white">{connection.state}</span>
              </div>
            )}
            {connection.direction && (
              <div className="flex justify-between text-sm">
                <span className="text-gray-400">Direction</span>
                <span className="text-white">{connection.direction}</span>
              </div>
            )}
          </div>
        </div>

        {/* Actions */}
        <div className="space-y-2">
          <Button className="w-full rounded-xl bg-red-500/20 text-red-300 hover:bg-red-500/30">
            <Ban className="mr-2 h-4 w-4" />
            Block Destination
          </Button>
          <Button className="w-full rounded-xl bg-yellow-500/20 text-yellow-300 hover:bg-yellow-500/30">
            <Lock className="mr-2 h-4 w-4" />
            Isolate Process
          </Button>
        </div>
      </div>
    </div>
  );
};

export default SignalsFeed;
