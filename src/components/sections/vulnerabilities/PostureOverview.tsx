// Posture Overview - Dashboard with "fix now" list and security posture metrics

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import {
  Shield, AlertTriangle, CheckCircle2, Clock,
  TrendingUp, Package, ExternalLink, RefreshCw
} from 'lucide-react';
import { ScanStatistics, PrioritizedFinding, Misconfiguration } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

interface PostureOverviewProps {
  stats: ScanStatistics | null;
  onRescan: () => void;
}

const PostureOverview: React.FC<PostureOverviewProps> = ({ stats, onRescan }) => {
  const [fixNowList, setFixNowList] = useState<PrioritizedFinding[]>([]);
  const [misconfigs, setMisconfigs] = useState<Misconfiguration[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [fixes, configs] = await Promise.all([
        invoke<PrioritizedFinding[]>('get_fix_now_list'),
        invoke<Misconfiguration[]>('scan_misconfigurations'),
      ]);

      setFixNowList(fixes);
      setMisconfigs(configs.filter(c => c.severity === 'Critical' || c.severity === 'High'));
    } catch (error) {
      console.error('Failed to load posture data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Calculate security score (0-100)
  const calculateSecurityScore = (): number => {
    if (!stats) return 100;

    const criticalWeight = 15;
    const highWeight = 10;
    const mediumWeight = 5;
    const lowWeight = 1;
    const misconfigWeight = 8;

    const vulnerabilityDeduction =
      stats.critical * criticalWeight +
      stats.high * highWeight +
      stats.medium * mediumWeight +
      stats.low * lowWeight;

    const misconfigDeduction = misconfigs.length * misconfigWeight;

    const totalDeduction = vulnerabilityDeduction + misconfigDeduction;
    const score = Math.max(0, 100 - totalDeduction);

    return Math.round(score);
  };

  const securityScore = calculateSecurityScore();
  const scoreColor =
    securityScore >= 80 ? 'text-green-400' :
    securityScore >= 60 ? 'text-yellow-400' :
    securityScore >= 40 ? 'text-orange-400' : 'text-red-400';

  const scoreLabel =
    securityScore >= 80 ? 'Excellent' :
    securityScore >= 60 ? 'Good' :
    securityScore >= 40 ? 'Fair' : 'Poor';

  return (
    <div className="space-y-6">
      {/* Security Score Card */}
      <div className="rounded-2xl border border-monitor-500/20 bg-gradient-to-br from-monitor-600/10 to-purple-600/10 p-6">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm text-gray-400">Security Posture Score</div>
            <div className={`mt-2 text-5xl font-bold ${scoreColor}`}>
              {securityScore}
              <span className="text-2xl">/100</span>
            </div>
            <div className="mt-2 flex items-center gap-2">
              <Badge className="rounded-full bg-monitor-600/20 text-monitor-300">
                {scoreLabel}
              </Badge>
              {securityScore < 80 && (
                <span className="text-xs text-gray-400">
                  {fixNowList.length} critical items need attention
                </span>
              )}
            </div>
          </div>

          <div className="flex flex-col items-end gap-4">
            <Shield className={`h-20 w-20 ${scoreColor} opacity-30`} />
            <Button
              onClick={onRescan}
              className="rounded-lg bg-monitor-600 text-white hover:bg-monitor-700"
              size="sm"
            >
              <RefreshCw className="mr-2 h-4 w-4" />
              Rescan
            </Button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-6">
          <div className="h-3 w-full overflow-hidden rounded-full bg-gray-700">
            <div
              className={`h-full transition-all duration-500 ${
                securityScore >= 80 ? 'bg-green-500' :
                securityScore >= 60 ? 'bg-yellow-500' :
                securityScore >= 40 ? 'bg-orange-500' : 'bg-red-500'
              }`}
              style={{ width: `${securityScore}%` }}
            />
          </div>
        </div>
      </div>

      {/* Fix Now List */}
      <div className="rounded-2xl border border-red-500/20 bg-red-500/5 p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-red-400" />
            <h3 className="text-lg font-semibold text-white">Fix Now</h3>
          </div>
          <Badge className="rounded-full bg-red-500/20 text-red-300">
            {fixNowList.length} Critical
          </Badge>
        </div>

        {loading ? (
          <div className="py-8 text-center text-gray-400">Loading critical findings...</div>
        ) : fixNowList.length === 0 ? (
          <div className="py-8 text-center">
            <CheckCircle2 className="mx-auto h-12 w-12 text-green-400" />
            <p className="mt-4 text-white">No critical vulnerabilities</p>
            <p className="mt-1 text-sm text-gray-400">
              Your system is protected against known critical threats
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {fixNowList.slice(0, 5).map((finding) => (
              <CriticalFindingCard key={finding.finding.id} finding={finding} />
            ))}
          </div>
        )}
      </div>

      {/* Grid: Misconfigurations + Exposed Services */}
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        {/* Critical Misconfigurations */}
        <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
          <div className="mb-4 flex items-center gap-2">
            <Shield className="h-5 w-5 text-yellow-400" />
            <h3 className="text-lg font-semibold text-white">Misconfigurations</h3>
          </div>

          {misconfigs.length === 0 ? (
            <div className="py-6 text-center text-gray-400 text-sm">
              No critical misconfigurations detected
            </div>
          ) : (
            <div className="space-y-2">
              {misconfigs.slice(0, 3).map((config) => (
                <MisconfigCard key={config.id} config={config} />
              ))}
            </div>
          )}
        </div>

        {/* Statistics */}
        <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-6">
          <div className="mb-4 flex items-center gap-2">
            <TrendingUp className="h-5 w-5 text-monitor-400" />
            <h3 className="text-lg font-semibold text-white">Statistics</h3>
          </div>

          {stats && (
            <div className="space-y-3">
              <StatRow label="Total Packages Scanned" value={stats.total_vulnerabilities} />
              <StatRow label="Critical Vulnerabilities" value={stats.critical} color="red" />
              <StatRow label="High Vulnerabilities" value={stats.high} color="orange" />
              <StatRow label="Medium Vulnerabilities" value={stats.medium} color="yellow" />
              <StatRow label="Exploitable (KEV/PoC)" value={stats.exploitable} color="red" />
              <StatRow label="Fixes Available" value={stats.fix_available} color="green" />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

interface CriticalFindingCardProps {
  finding: PrioritizedFinding;
}

const CriticalFindingCard: React.FC<CriticalFindingCardProps> = ({ finding }) => {
  const { cve, affected_package } = finding.finding;

  const priorityColors = {
    Critical: 'bg-red-500/20 text-red-300 border-red-500/30',
    High: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    Medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    Low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    Info: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  };

  return (
    <div className="rounded-xl border border-red-700/50 bg-red-500/10 p-4">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-white">{cve.id}</span>
            {cve.cisa_kev && (
              <Badge className="rounded-full bg-red-600/30 text-red-200 text-xs">
                CISA KEV
              </Badge>
            )}
            {cve.has_exploit && (
              <Badge className="rounded-full bg-orange-600/30 text-orange-200 text-xs">
                Exploit Available
              </Badge>
            )}
          </div>

          <div className="mt-1 text-sm text-gray-300">
            {affected_package.name} {affected_package.version}
          </div>

          <div className="mt-2 text-xs text-gray-400 line-clamp-2">
            {cve.description}
          </div>

          <div className="mt-3 flex items-center gap-3 text-xs">
            <div className="flex items-center gap-1">
              <Package className="h-3 w-3 text-gray-500" />
              <span className="text-gray-400">CVSS: {cve.cvss_score?.toFixed(1)}</span>
            </div>
            <div className="flex items-center gap-1">
              <TrendingUp className="h-3 w-3 text-gray-500" />
              <span className="text-gray-400">
                Risk: {finding.priority_score.toFixed(0)}
              </span>
            </div>
          </div>
        </div>

        <Badge className={`rounded-full text-xs ${priorityColors[finding.priority_level]}`}>
          {finding.priority_level}
        </Badge>
      </div>
    </div>
  );
};

interface MisconfigCardProps {
  config: Misconfiguration;
}

const MisconfigCard: React.FC<MisconfigCardProps> = ({ config }) => {
  return (
    <div className="rounded-lg border border-yellow-700/50 bg-yellow-500/10 p-3">
      <div className="flex items-start gap-2">
        <AlertTriangle className="h-4 w-4 text-yellow-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="font-medium text-white text-sm">{config.title}</div>
          <div className="mt-1 text-xs text-gray-400">{config.affected_component}</div>
        </div>
      </div>
    </div>
  );
};

interface StatRowProps {
  label: string;
  value: number;
  color?: 'red' | 'orange' | 'yellow' | 'green';
}

const StatRow: React.FC<StatRowProps> = ({ label, value, color }) => {
  const colorClass = color
    ? {
        red: 'text-red-400',
        orange: 'text-orange-400',
        yellow: 'text-yellow-400',
        green: 'text-green-400',
      }[color]
    : 'text-white';

  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-gray-400">{label}</span>
      <span className={`font-semibold ${colorClass}`}>{value.toLocaleString()}</span>
    </div>
  );
};

export default PostureOverview;
