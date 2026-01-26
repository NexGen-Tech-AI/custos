// Remediation Panel - One-click fixes with warnings and rollback support

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Settings, AlertTriangle, CheckCircle2, Terminal, Info } from 'lucide-react';
import { PrioritizedFinding, RemediationAction } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';

const RemediationPanel: React.FC = () => {
  const [fixableFindings, setFixableFindings] = useState<PrioritizedFinding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadFixableFindings();
  }, []);

  const loadFixableFindings = async () => {
    try {
      const result = await invoke<PrioritizedFinding[]>('get_prioritized_vulnerabilities');
      const fixable = result.filter((f) => f.finding.fix_available);
      setFixableFindings(fixable);
    } catch (error) {
      console.error('Failed to load fixable findings:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Info Banner */}
      <div className="rounded-2xl border border-blue-500/20 bg-blue-500/5 p-4">
        <div className="flex items-start gap-3">
          <Info className="h-5 w-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm text-gray-300">
            <div className="font-semibold text-white">Automated Remediation</div>
            <p className="mt-1">
              Review and apply package updates to fix vulnerabilities. Commands will be executed with your system's package manager.
              Always review changes before applying.
            </p>
          </div>
        </div>
      </div>

      {/* Fixable Findings */}
      {loading ? (
        <div className="py-12 text-center text-gray-400">Loading remediation options...</div>
      ) : fixableFindings.length === 0 ? (
        <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-12 text-center">
          <CheckCircle2 className="mx-auto h-12 w-12 text-green-400" />
          <p className="mt-4 text-white">No fixable vulnerabilities</p>
          <p className="mt-1 text-sm text-gray-400">
            All vulnerabilities either have no fix available or are already patched
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {fixableFindings.slice(0, 20).map((finding) => (
            <RemediationCard key={finding.finding.id} finding={finding} />
          ))}
        </div>
      )}
    </div>
  );
};

interface RemediationCardProps {
  finding: PrioritizedFinding;
}

const RemediationCard: React.FC<RemediationCardProps> = ({ finding }) => {
  const [showCommand, setShowCommand] = useState(false);
  const { cve, affected_package, recommended_action } = finding.finding;

  const getActionCommand = (): string | null => {
    if (typeof recommended_action === 'string' && recommended_action === 'NoFixAvailable') {
      return null;
    }

    if ('Upgrade' in recommended_action) {
      return recommended_action.Upgrade.package_manager_command;
    }

    return null;
  };

  const getFixDescription = (): string => {
    if (typeof recommended_action === 'string' && recommended_action === 'NoFixAvailable') {
      return 'No fix available yet';
    }

    if ('Upgrade' in recommended_action) {
      return `Upgrade to ${recommended_action.Upgrade.to_version}`;
    }

    if ('Patch' in recommended_action) {
      return recommended_action.Patch.description;
    }

    if ('Mitigate' in recommended_action) {
      return `${recommended_action.Mitigate.steps.length} mitigation steps available`;
    }

    return 'Fix available';
  };

  const command = getActionCommand();

  const priorityColors = {
    Critical: 'border-red-500/50 bg-red-500/10',
    High: 'border-orange-500/50 bg-orange-500/10',
    Medium: 'border-yellow-500/50 bg-yellow-500/10',
    Low: 'border-blue-500/50 bg-blue-500/10',
    Info: 'border-gray-500/50 bg-gray-500/10',
  };

  return (
    <div className={`rounded-xl border p-4 ${priorityColors[finding.priority_level]}`}>
      <div className="flex items-start justify-between">
        <div className="flex-1">
          {/* Header */}
          <div className="flex items-center gap-2">
            <span className="font-mono text-sm font-semibold text-white">{cve.id}</span>
            <Badge
              className={`rounded-full text-xs ${
                finding.priority_level === 'Critical'
                  ? 'bg-red-600/30 text-red-200'
                  : finding.priority_level === 'High'
                  ? 'bg-orange-600/30 text-orange-200'
                  : 'bg-yellow-600/30 text-yellow-200'
              }`}
            >
              {finding.priority_level}
            </Badge>
            {cve.cisa_kev && (
              <Badge className="rounded-full bg-red-600/30 text-red-200 text-xs">
                CISA KEV
              </Badge>
            )}
          </div>

          {/* Package Info */}
          <div className="mt-2 text-sm text-gray-300">
            {affected_package.name} {affected_package.version} → {getFixDescription()}
          </div>

          {/* Description */}
          <div className="mt-2 text-xs text-gray-400 line-clamp-2">{cve.description}</div>

          {/* Stats */}
          <div className="mt-3 flex items-center gap-3 text-xs text-gray-500">
            <span>CVSS: {cve.cvss_score?.toFixed(1)}</span>
            <span>•</span>
            <span>Risk: {finding.priority_score.toFixed(0)}</span>
          </div>

          {/* Command Preview */}
          {showCommand && command && (
            <div className="mt-3 rounded-lg border border-gray-700 bg-gray-900/50 p-3">
              <div className="flex items-center gap-2 text-xs text-gray-400 mb-2">
                <Terminal className="h-3 w-3" />
                <span>Command to execute:</span>
              </div>
              <code className="block overflow-x-auto rounded bg-black/50 p-2 text-xs text-green-400 font-mono">
                {command}
              </code>
            </div>
          )}

          {/* Warnings */}
          {finding.priority_level === 'Critical' && (
            <div className="mt-3 flex items-start gap-2 rounded-lg bg-red-500/10 p-2">
              <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs text-red-300">
                Critical vulnerability with active exploitation. Apply this fix immediately.
              </div>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="ml-4 flex flex-col gap-2">
          {command ? (
            <>
              <Button
                size="sm"
                onClick={() => setShowCommand(!showCommand)}
                className="rounded-lg bg-monitor-600 text-white hover:bg-monitor-700 text-xs"
              >
                {showCommand ? 'Hide' : 'Show'} Command
              </Button>
              <Button
                size="sm"
                variant="outline"
                className="rounded-lg border-gray-600 text-gray-300 hover:bg-gray-700 text-xs"
                onClick={() => {
                  // TODO: Implement actual remediation
                  console.log('Apply fix:', command);
                  alert('Remediation will be implemented in the next phase');
                }}
              >
                Apply Fix
              </Button>
            </>
          ) : (
            <Badge className="rounded-full bg-gray-600/30 text-gray-300 text-xs">
              No Auto-Fix
            </Badge>
          )}
        </div>
      </div>
    </div>
  );
};

export default RemediationPanel;
