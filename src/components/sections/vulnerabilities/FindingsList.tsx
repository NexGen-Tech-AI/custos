// Findings List - Comprehensive table of all CVEs and misconfigurations

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Search, Filter, Package, AlertTriangle, ExternalLink, Sparkles } from 'lucide-react';
import { AnimatePresence } from 'framer-motion';
import { PrioritizedFinding, PackageVulnerabilityGroup } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import VulnerabilityChat from './VulnerabilityChat';

const FindingsList: React.FC = () => {
  const [findings, setFindings] = useState<PackageVulnerabilityGroup[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [loading, setLoading] = useState(true);
  const [chatVulnerability, setChatVulnerability] = useState<any | null>(null);

  useEffect(() => {
    loadFindings();
  }, []);

  const loadFindings = async () => {
    try {
      const result = await invoke<PackageVulnerabilityGroup[]>('get_vulnerabilities_by_package');
      setFindings(result);
    } catch (error) {
      console.error('Failed to load findings:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredFindings = findings.filter((group) => {
    if (searchQuery && !group.package_name.toLowerCase().includes(searchQuery.toLowerCase())) {
      return false;
    }
    if (severityFilter !== 'all') {
      const hasSeverity = group.findings.some(
        (f) => f.priority_level.toLowerCase() === severityFilter.toLowerCase()
      );
      if (!hasSeverity) return false;
    }
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
            placeholder="Search packages..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-xl border border-gray-700 bg-gray-800 py-2 pl-10 pr-4 text-sm text-white placeholder-gray-400 focus:border-monitor-500 focus:outline-none focus:ring-1 focus:ring-monitor-500"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-xl border border-gray-700 bg-gray-800 px-4 py-2 text-sm text-white focus:border-monitor-500 focus:outline-none focus:ring-1 focus:ring-monitor-500"
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>

        <Button onClick={loadFindings} className="rounded-xl bg-monitor-600 text-white hover:bg-monitor-700">
          <Filter className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {/* Findings Table */}
      {loading ? (
        <div className="py-12 text-center text-gray-400">Loading findings...</div>
      ) : filteredFindings.length === 0 ? (
        <div className="rounded-2xl border border-gray-700 bg-gray-800/50 p-12 text-center">
          <Package className="mx-auto h-12 w-12 text-gray-600" />
          <p className="mt-4 text-gray-400">No vulnerabilities found</p>
          <p className="mt-1 text-sm text-gray-500">
            {searchQuery || severityFilter !== 'all'
              ? 'Try adjusting your filters'
              : 'Your system appears to be secure'}
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredFindings.map((group) => (
            <PackageGroupCard key={group.package_name} group={group} onOpenChat={setChatVulnerability} />
          ))}
        </div>
      )}

      {/* AI Chat Modal */}
      <AnimatePresence>
        {chatVulnerability && (
          <VulnerabilityChat
            vulnerability={chatVulnerability}
            onClose={() => setChatVulnerability(null)}
          />
        )}
      </AnimatePresence>
    </div>
  );
};

interface PackageGroupCardProps {
  group: PackageVulnerabilityGroup;
  onOpenChat: (vulnerability: any) => void;
}

const PackageGroupCard: React.FC<PackageGroupCardProps> = ({ group, onOpenChat }) => {
  const [expanded, setExpanded] = useState(false);

  const highestFinding = group.findings[0];
  const criticalCount = group.findings.filter((f) => f.priority_level === 'Critical').length;
  const highCount = group.findings.filter((f) => f.priority_level === 'High').length;

  return (
    <div className="rounded-xl border border-gray-700 bg-gray-800/50 overflow-hidden">
      {/* Package Header */}
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-800/70 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-4">
          <Package className="h-5 w-5 text-monitor-400" />
          <div>
            <div className="font-semibold text-white">{group.package_name}</div>
            <div className="text-xs text-gray-400">
              {group.vulnerability_count} vulnerabilities • Priority: {group.highest_priority.toFixed(0)}
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {criticalCount > 0 && (
            <Badge className="rounded-full bg-red-500/20 text-red-300 text-xs">
              {criticalCount} Critical
            </Badge>
          )}
          {highCount > 0 && (
            <Badge className="rounded-full bg-orange-500/20 text-orange-300 text-xs">
              {highCount} High
            </Badge>
          )}
          <span className="text-gray-500">{expanded ? '▼' : '▶'}</span>
        </div>
      </div>

      {/* Expanded Vulnerabilities */}
      {expanded && (
        <div className="border-t border-gray-700 bg-gray-900/50 p-4 space-y-2">
          {group.findings.map((finding) => (
            <VulnerabilityRow key={finding.finding.id} finding={finding} onOpenChat={onOpenChat} />
          ))}
        </div>
      )}
    </div>
  );
};

interface VulnerabilityRowProps {
  finding: PrioritizedFinding;
  onOpenChat: (vulnerability: any) => void;
}

const VulnerabilityRow: React.FC<VulnerabilityRowProps> = ({ finding, onOpenChat }) => {
  const { cve } = finding.finding;

  const priorityColors = {
    Critical: 'bg-red-500/20 text-red-300 border-red-500/30',
    High: 'bg-orange-500/20 text-orange-300 border-orange-500/30',
    Medium: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    Low: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    Info: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  };

  const handleAskAI = () => {
    // Prepare vulnerability data for chat
    const vulnerabilityData = {
      cve_id: cve.id,
      severity: finding.priority_level,
      summary: cve.description || '',
      package_name: finding.finding.package_name || 'Unknown',
      package_version: finding.finding.package_version || 'Unknown',
      affected_versions: finding.finding.affected_versions,
    };
    onOpenChat(vulnerabilityData);
  };

  return (
    <div className="flex items-start justify-between rounded-lg border border-gray-700/50 bg-gray-800/30 p-3">
      <div className="flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-sm font-semibold text-white">{cve.id}</span>
          {cve.cisa_kev && (
            <Badge className="rounded-full bg-red-600/30 text-red-200 text-xs">KEV</Badge>
          )}
          {cve.has_exploit && (
            <Badge className="rounded-full bg-orange-600/30 text-orange-200 text-xs">Exploit</Badge>
          )}
          <Badge className={`rounded-full text-xs ${priorityColors[finding.priority_level]}`}>
            {finding.priority_level}
          </Badge>
        </div>

        <div className="mt-1 text-xs text-gray-400">{cve.description}</div>

        <div className="mt-2 flex items-center gap-3 text-xs text-gray-500">
          <span>CVSS: {cve.cvss_score?.toFixed(1)}</span>
          <span>•</span>
          <span>Risk Score: {finding.priority_score.toFixed(0)}</span>
          {cve.epss_score && (
            <>
              <span>•</span>
              <span>EPSS: {(cve.epss_score * 100).toFixed(1)}%</span>
            </>
          )}
        </div>
      </div>

      <div className="ml-4 flex items-center gap-2">
        <button
          onClick={handleAskAI}
          className="flex items-center gap-1 rounded-lg bg-purple-600/20 px-3 py-1.5 text-xs text-purple-300 transition-colors hover:bg-purple-600/30 hover:text-purple-200"
          title="Ask AI about this vulnerability"
        >
          <Sparkles className="h-3.5 w-3.5" />
          Ask AI
        </button>

        {cve.references.length > 0 && (
          <a
            href={cve.references[0]}
            target="_blank"
            rel="noopener noreferrer"
            className="flex-shrink-0 text-monitor-400 hover:text-monitor-300"
          >
            <ExternalLink className="h-4 w-4" />
          </a>
        )}
      </div>
    </div>
  );
};

export default FindingsList;
