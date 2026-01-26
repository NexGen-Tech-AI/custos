import React, { useMemo, useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { invoke } from '@tauri-apps/api/core';
import {
  Shield,
  Bell,
  Search,
  Filter,
  Clock,
  Check,
  AlertTriangle,
  TrendingUp,
  ChevronRight,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";

// Backend types
interface ThreatEvent {
  id: string;
  timestamp: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  category: string;
  title: string;
  description: string;
  detection_method: any;
  process_id?: number;
  process_name?: string;
  process_path?: string;
  parent_process?: string;
  user?: string;
  network_connection?: {
    local_address: string;
    local_port: number;
    remote_address: string;
    remote_port: number;
    protocol: string;
  };
  file_path?: string;
  file_hash?: string;
  ai_analysis?: {
    analysis: string;
    recommendations: string[];
  };
  threat_intel?: {
    source: string;
    reputation_score: number;
    categories: string[];
  };
  mitre_tactics: string[];
  mitre_techniques: string[];
  confidence: number;
  metadata: Record<string, string>;
  recommended_actions: string[];
  status: string;
}

interface Alert {
  id: string;
  threat_event: ThreatEvent;
  created_at: string;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: string;
  notes: { content: string; author: string; created_at: string }[];
}

interface ThreatStats {
  total_threats: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

const severityColors: Record<string, string> = {
  Critical: "bg-red-500/20 text-red-200 border-red-500/30",
  High: "bg-orange-500/20 text-orange-200 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-200 border-yellow-500/30",
  Low: "bg-emerald-500/15 text-emerald-200 border-emerald-500/25",
  Info: "bg-blue-500/15 text-blue-200 border-blue-500/25",
};

const confidenceColors: Record<string, string> = {
  A: "bg-monitor-500/20 text-monitor-200 border-monitor-500/30",
  B: "bg-slate-500/20 text-slate-200 border-slate-500/30",
  C: "bg-zinc-500/20 text-zinc-200 border-zinc-500/30",
};

function Stat({ label, value, sub, icon: Icon }: any) {
  return (
    <Card className="rounded-2xl border-gray-700 bg-gray-800/50 shadow-sm">
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-xs text-gray-400">{label}</div>
            <div className="mt-1 text-2xl font-semibold tracking-tight text-white">
              {value}
            </div>
            {sub ? <div className="mt-1 text-xs text-gray-500">{sub}</div> : null}
          </div>
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gray-700/50 text-gray-300">
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function Pill({ label, tone }: { label: string; tone: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] ${tone}`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-white/70" />
      {label}
    </span>
  );
}

// Helper to convert confidence number to letter grade
function getConfidenceGrade(confidence: number): string {
  if (confidence >= 0.8) return 'A';
  if (confidence >= 0.6) return 'B';
  return 'C';
}

// Helper to format timestamps
function formatTimeAgo(timestamp: string): string {
  const date = new Date(timestamp);
  const seconds = Math.floor((new Date().getTime() - date.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

// Helper to get unique hosts from threats
function getAffectedHosts(threats: ThreatEvent[]): Set<string> {
  const hosts = new Set<string>();
  threats.forEach(threat => {
    if (threat.metadata?.hostname) hosts.add(threat.metadata.hostname);
    if (threat.process_name) hosts.add(threat.process_name);
  });
  return hosts;
}

export default function ThreatDetectionSection() {
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [selected, setSelected] = useState<ThreatEvent | null>(null);
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);

  // Fetch data from backend
  useEffect(() => {
    const fetchData = async () => {
      try {
        const [threatsData, alertsData, statsData] = await Promise.all([
          invoke<ThreatEvent[]>('get_recent_threats', { limit: 100 }),
          invoke<Alert[]>('get_all_alerts'),
          invoke<ThreatStats>('get_threat_statistics'),
        ]);
        setThreats(threatsData);
        setAlerts(alertsData);
        setStats(statsData);
        if (threatsData.length > 0 && !selected) {
          setSelected(threatsData[0]);
        }
      } catch (error) {
        console.error('Failed to fetch threat data:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  const filtered = useMemo(() => {
    if (!query.trim()) return threats;
    const q = query.toLowerCase();
    return threats.filter(
      (threat) =>
        threat.title.toLowerCase().includes(q) ||
        threat.id.toLowerCase().includes(q) ||
        threat.process_name?.toLowerCase().includes(q) ||
        threat.description.toLowerCase().includes(q)
    );
  }, [query, threats]);

  // Calculate stats
  const affectedHosts = getAffectedHosts(threats);
  const criticalCount = stats?.by_severity['Critical'] || 0;
  const highCount = stats?.by_severity['High'] || 0;
  const unacknowledgedCount = alerts.filter(a => !a.acknowledged).length;
  const last24h = threats.filter(t => {
    const time = new Date(t.timestamp).getTime();
    return Date.now() - time < 86400000;
  }).length;

  // Calculate posture score
  const postureScore = useMemo(() => {
    let score = 100;
    score -= (stats?.total_threats || 0) * 2;
    score -= criticalCount * 15;
    score -= highCount * 10;
    score -= unacknowledgedCount * 5;
    return Math.max(0, Math.min(100, score));
  }, [stats, criticalCount, highCount, unacknowledgedCount]);

  // Group threats into incidents (simplified - by category)
  const incidents = useMemo(() => {
    return threats.map(threat => ({
      ...threat,
      hosts: 1, // Simplified - would need multi-host tracking
      firstSeen: formatTimeAgo(threat.timestamp),
      chain: [threat.category],
    }));
  }, [threats]);

  // Build timeline from selected threat
  const timeline = useMemo(() => {
    if (!selected) return [];
    const events = [];

    if (selected.process_name) {
      events.push({
        t: formatTimeAgo(selected.timestamp),
        s: "Process",
        msg: `${selected.process_name} executed${selected.process_path ? ` from ${selected.process_path}` : ''}`,
        sev: selected.severity,
      });
    }

    if (selected.file_path) {
      events.push({
        t: formatTimeAgo(selected.timestamp),
        s: "File",
        msg: `File operation: ${selected.file_path}`,
        sev: selected.severity,
      });
    }

    if (selected.network_connection) {
      events.push({
        t: formatTimeAgo(selected.timestamp),
        s: "Network",
        msg: `Connection to ${selected.network_connection.remote_address}:${selected.network_connection.remote_port}`,
        sev: selected.severity,
      });
    }

    return events;
  }, [selected]);

  // Build evidence from selected threat
  const evidence = useMemo(() => {
    if (!selected) return [];
    const ev = [];

    if (selected.process_id) {
      ev.push({
        kind: "Process",
        key: "pid",
        value: selected.process_id.toString(),
        detail: selected.process_path || selected.process_name || 'Unknown process',
      });
    }

    if (selected.file_hash) {
      ev.push({
        kind: "File",
        key: "sha256",
        value: selected.file_hash.substring(0, 8) + '...',
        detail: selected.file_path || 'Unknown file',
      });
    }

    if (selected.network_connection) {
      ev.push({
        kind: "Network",
        key: "dst",
        value: `${selected.network_connection.remote_address}:${selected.network_connection.remote_port}`,
        detail: `Protocol: ${selected.network_connection.protocol}`,
      });
    }

    if (selected.user) {
      ev.push({
        kind: "Identity",
        key: "user",
        value: selected.user,
        detail: "Process owner",
      });
    }

    return ev;
  }, [selected]);

  // Handle threat acknowledgment
  const handleAcknowledge = async (threatId: string) => {
    try {
      const alert = alerts.find(a => a.threat_event.id === threatId);
      if (alert) {
        await invoke('acknowledge_alert', {
          alertId: alert.id,
          user: 'current_user', // TODO: Get from auth context
        });
        // Refresh alerts
        const newAlerts = await invoke<Alert[]>('get_all_alerts');
        setAlerts(newAlerts);
      }
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
    }
  };

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="text-gray-400">Loading threat detection portal...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen w-full bg-gray-900">
      <div className="relative mx-auto max-w-full px-4 py-6">
        {/* Top bar */}
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35 }}
          className="flex items-center justify-between mb-6"
        >
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-monitor-600/20">
              <Shield className="h-5 w-5 text-monitor-400" />
            </div>
            <div>
              <div className="text-sm font-semibold text-white">CUSTOS</div>
              <div className="text-xs text-gray-400">Threat Detection Portal • Real-time Security Intelligence</div>
            </div>
          </div>

          <div className="hidden items-center gap-2 md:flex">
            <Badge className="rounded-full bg-monitor-600/20 text-monitor-200 border-monitor-500/30">
              <Shield className="mr-1 h-3 w-3" />
              Active Monitoring
            </Badge>
            <Button className="rounded-2xl bg-gray-700 text-white hover:bg-gray-600">
              <Bell className="mr-2 h-4 w-4" />
              Alerts ({unacknowledgedCount})
            </Button>
          </div>
        </motion.div>

        {/* Stats */}
        <div className="mt-6 grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
          <Stat
            label="Total Threats"
            value={stats?.total_threats || 0}
            sub={`${criticalCount} critical • ${highCount} high`}
            icon={Shield}
          />
          <Stat
            label="Open Incidents"
            value={unacknowledgedCount}
            sub={`${criticalCount} require immediate action`}
            icon={AlertTriangle}
          />
          <Stat
            label="Alerts (24h)"
            value={last24h}
            sub={`Across ${affectedHosts.size} hosts`}
            icon={Bell}
          />
          <Stat
            label="Security Posture"
            value={`${postureScore}%`}
            sub={postureScore >= 80 ? 'Good' : postureScore >= 60 ? 'Fair' : 'Needs attention'}
            icon={TrendingUp}
          />
        </div>

        {/* Main layout */}
        <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-12">
          {/* Center queue */}
          <Card className="rounded-2xl border-gray-700 bg-gray-800/50 lg:col-span-7">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between gap-3">
                <CardTitle className="text-base text-white">Threat Queue</CardTitle>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-gray-400" />
                    <Input
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="Search threats, processes, IDs…"
                      className="h-9 w-[220px] rounded-xl border-gray-600 bg-gray-700/50 pl-9 text-white placeholder:text-gray-400"
                    />
                  </div>
                  <Button className="h-9 rounded-xl bg-gray-700 text-white hover:bg-gray-600">
                    <Filter className="mr-2 h-4 w-4" />
                    Filter
                  </Button>
                </div>
              </div>
              <div className="mt-2 text-xs text-gray-400">
                Real-time threat detection from behavioral analysis, signatures, and AI
              </div>
            </CardHeader>

            <CardContent className="p-2 max-h-[600px] overflow-y-auto">
              <div className="space-y-2">
                {filtered.length === 0 ? (
                  <div className="p-8 text-center text-gray-400">
                    {query ? 'No threats match your search' : 'No threats detected'}
                  </div>
                ) : (
                  filtered.map((threat) => {
                    const active = threat.id === selected?.id;
                    const confidenceGrade = getConfidenceGrade(threat.confidence);

                    return (
                      <button
                        key={threat.id}
                        onClick={() => setSelected(threat)}
                        className={`w-full rounded-2xl border p-3 text-left transition ${
                          active
                            ? "border-monitor-500/40 bg-monitor-500/10"
                            : "border-gray-700 bg-gray-800/50 hover:bg-gray-700/50"
                        }`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-sm font-semibold text-white">
                                {threat.title}
                              </span>
                              <Pill label={threat.severity} tone={severityColors[threat.severity]} />
                              <Pill label={`Conf ${confidenceGrade}`} tone={confidenceColors[confidenceGrade]} />
                            </div>
                            <div className="mt-1 line-clamp-2 text-xs text-gray-400">
                              {threat.description}
                            </div>
                          </div>
                          <div className="flex flex-col items-end gap-1 text-xs text-gray-400">
                            <div className="flex items-center gap-1">
                              <Clock className="h-3.5 w-3.5" />
                              {formatTimeAgo(threat.timestamp)}
                            </div>
                          </div>
                        </div>

                        <div className="mt-3 flex flex-wrap items-center gap-2">
                          <Badge className="rounded-full bg-gray-700/50 text-gray-300 hover:bg-gray-700/50">
                            {threat.category}
                          </Badge>
                          <div className="ml-auto flex items-center gap-2">
                            {threat.mitre_techniques.slice(0, 3).map((t) => (
                              <Badge
                                key={t}
                                className="rounded-full bg-gray-800/50 text-gray-400 hover:bg-gray-800/50"
                              >
                                {t}
                              </Badge>
                            ))}
                            <Badge className="rounded-full bg-gray-700/50 text-gray-300 hover:bg-gray-700/50">
                              {threat.id.substring(0, 8)}
                            </Badge>
                          </div>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </CardContent>
          </Card>

          {/* Right details */}
          <Card className="rounded-2xl border-gray-700 bg-gray-800/50 lg:col-span-5">
            {selected ? (
              <>
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <CardTitle className="text-base text-white">{selected.id.substring(0, 12)}</CardTitle>
                      <div className="mt-1 text-sm font-semibold text-white">
                        {selected.title}
                      </div>
                      <div className="mt-2 flex flex-wrap items-center gap-2">
                        <Pill label={selected.severity} tone={severityColors[selected.severity]} />
                        <Pill label={`Confidence ${getConfidenceGrade(selected.confidence)}`} tone={confidenceColors[getConfidenceGrade(selected.confidence)]} />
                        {selected.process_name && (
                          <Badge className="rounded-full bg-gray-700/50 text-gray-300 hover:bg-gray-700/50">
                            Process: {selected.process_name}
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div className="flex flex-col gap-2">
                      <Button
                        onClick={() => handleAcknowledge(selected.id)}
                        className="rounded-xl bg-monitor-600 text-white hover:bg-monitor-700"
                      >
                        <Check className="mr-2 h-4 w-4" />
                        Acknowledge
                      </Button>
                    </div>
                  </div>

                  {selected.ai_analysis && (
                    <div className="mt-3 rounded-2xl border border-gray-700 bg-gray-700/30 p-3">
                      <div className="text-xs font-medium text-gray-300">AI Assessment</div>
                      <div className="mt-1 text-xs text-gray-400">
                        {selected.ai_analysis.analysis}
                      </div>
                    </div>
                  )}

                  {!selected.ai_analysis && selected.description && (
                    <div className="mt-3 rounded-2xl border border-gray-700 bg-gray-700/30 p-3">
                      <div className="text-xs font-medium text-gray-300">Threat Description</div>
                      <div className="mt-1 text-xs text-gray-400">
                        {selected.description}
                      </div>
                    </div>
                  )}
                </CardHeader>

                <CardContent className="p-3">
                  <Tabs defaultValue="evidence" className="w-full">
                    <TabsList className="grid w-full grid-cols-3 rounded-2xl bg-gray-700/30">
                      <TabsTrigger value="evidence" className="rounded-2xl">
                        Evidence
                      </TabsTrigger>
                      <TabsTrigger value="timeline" className="rounded-2xl">
                        Timeline
                      </TabsTrigger>
                      <TabsTrigger value="actions" className="rounded-2xl">
                        Actions
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="evidence" className="mt-3">
                      <div className="space-y-2">
                        {evidence.length === 0 ? (
                          <div className="p-4 text-center text-xs text-gray-400">
                            No additional evidence available
                          </div>
                        ) : (
                          evidence.map((e, idx) => (
                            <div
                              key={idx}
                              className="rounded-2xl border border-gray-700 bg-gray-700/30 p-3"
                            >
                              <div className="flex items-center justify-between">
                                <div className="text-xs font-medium text-gray-300">{e.kind}</div>
                                <Badge className="rounded-full bg-gray-700/50 text-gray-300 hover:bg-gray-700/50">
                                  {e.key}
                                </Badge>
                              </div>
                              <div className="mt-1 font-mono text-xs text-white">{e.value}</div>
                              <div className="mt-1 text-xs text-gray-400">{e.detail}</div>
                            </div>
                          ))
                        )}
                      </div>
                    </TabsContent>

                    <TabsContent value="timeline" className="mt-3">
                      <div className="space-y-2">
                        {timeline.length === 0 ? (
                          <div className="p-4 text-center text-xs text-gray-400">
                            No timeline data available
                          </div>
                        ) : (
                          timeline.map((ev, idx) => (
                            <div
                              key={idx}
                              className="flex items-start justify-between gap-3 rounded-2xl border border-gray-700 bg-gray-700/30 p-3"
                            >
                              <div className="min-w-0">
                                <div className="text-xs text-gray-400">{ev.t}</div>
                                <div className="mt-1 text-sm font-semibold text-white">
                                  {ev.s}
                                </div>
                                <div className="mt-1 text-xs text-gray-400">{ev.msg}</div>
                              </div>
                              <Pill label={ev.sev} tone={severityColors[ev.sev] || severityColors.Medium} />
                            </div>
                          ))
                        )}
                      </div>
                    </TabsContent>

                    <TabsContent value="actions" className="mt-3">
                      <div className="space-y-3">
                        <div className="rounded-2xl border border-gray-700 bg-gray-700/30 p-3">
                          <div className="text-xs font-medium text-gray-300">Recommended next actions</div>
                          <div className="mt-2 grid gap-2">
                            {selected.recommended_actions.length === 0 ? (
                              <div className="p-2 text-xs text-gray-400">
                                No automated actions available
                              </div>
                            ) : (
                              selected.recommended_actions.map((action, idx) => (
                                <Button
                                  key={idx}
                                  className="w-full justify-start rounded-xl bg-gray-700/50 text-white hover:bg-gray-600/50"
                                >
                                  <ChevronRight className="mr-2 h-4 w-4" />
                                  {action}
                                </Button>
                              ))
                            )}
                          </div>
                          <div className="mt-2 text-[11px] text-gray-500">
                            All actions require confirmation and are logged
                          </div>
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </>
            ) : (
              <CardContent className="p-8 text-center">
                <div className="text-gray-400">Select a threat to view details</div>
              </CardContent>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}
