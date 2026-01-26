// Segments & Topology - Network visualization and segment management

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Network, Shield, Settings } from 'lucide-react';
import { SegmentPolicy, NetworkSegment } from '@/types';
import { Badge } from '@/components/ui/badge';

const SegmentsTopology: React.FC = () => {
  const [policies, setPolicies] = useState<SegmentPolicy[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    try {
      const result = await invoke<SegmentPolicy[]>('get_segment_policies');
      setPolicies(result);
    } catch (error) {
      console.error('Failed to load segment policies:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Coming Soon Banner */}
      <div className="rounded-2xl border border-monitor-500/20 bg-monitor-500/5 p-8 text-center">
        <Network className="mx-auto h-16 w-16 text-monitor-400" />
        <h3 className="mt-4 text-xl font-semibold text-white">Network Topology Visualization</h3>
        <p className="mt-2 text-gray-400">
          Visual network map with device grouping and segment policies
        </p>
        <Badge className="mt-4 rounded-full bg-monitor-600/20 text-monitor-300">
          Coming Soon
        </Badge>
      </div>

      {/* Segment Policies */}
      <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
        <div className="mb-4 flex items-center gap-2">
          <Shield className="h-5 w-5 text-monitor-400" />
          <h3 className="text-lg font-semibold text-white">Segment Policies</h3>
        </div>

        {loading ? (
          <div className="py-8 text-center text-gray-400">Loading policies...</div>
        ) : (
          <div className="space-y-3">
            {policies.map((policy, idx) => (
              <SegmentPolicyCard key={idx} policy={policy} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

interface SegmentPolicyCardProps {
  policy: SegmentPolicy;
}

const SegmentPolicyCard: React.FC<SegmentPolicyCardProps> = ({ policy }) => {
  return (
    <div className="rounded-xl border border-gray-700 bg-gray-800/30 p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="font-medium text-white">{policy.segment}</span>
            {policy.restrict_lateral && (
              <Badge className="rounded-full bg-yellow-500/20 text-yellow-300 text-xs">
                Lateral Movement Restricted
              </Badge>
            )}
            {policy.block_internet && (
              <Badge className="rounded-full bg-red-500/20 text-red-300 text-xs">
                Internet Blocked
              </Badge>
            )}
          </div>
          <div className="mt-1 text-xs text-gray-400">
            {policy.blocked_ports.length > 0 && `${policy.blocked_ports.length} blocked ports`}
            {policy.blocked_asns.length > 0 && ` • ${policy.blocked_asns.length} blocked ASNs`}
          </div>
        </div>

        <Settings className="h-5 w-5 text-gray-500" />
      </div>
    </div>
  );
};

export default SegmentsTopology;
