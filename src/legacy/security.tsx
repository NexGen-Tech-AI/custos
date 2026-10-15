// Legacy security UI, built only with VITE_LEGACY_SECURITY=1 (and the
// src-tauri feature "legacy-security", which provides its commands). Not
// type-checked by default: see tsconfig.legacy.json.
import { LayoutDashboard, Shield, Network, Search, Sparkles, FileText } from 'lucide-react';
import { DashboardSection } from '../components/sections/DashboardSection';
import ThreatDetectionSection from '../components/sections/ThreatDetectionSection';
import NetworkSecuritySection from '../components/sections/network-security/NetworkSecuritySection';
import VulnerabilitiesSection from '../components/sections/vulnerabilities/VulnerabilitiesSection';
import AIAnalysisSection from '../components/AIAnalysisSection';
import ReportsSection from '../components/sections/ReportsSection';
import { ScanProvider, useScan } from '../contexts/ScanContext';
import ScanProgressIndicator from '../components/ScanProgressIndicator';
import type { LegacyRegistry } from './types';

function ScanOverlay({ activeSection, onOpenSection }: { activeSection: string; onOpenSection: (id: string) => void }) {
  const { scanProgress, showFloatingIndicator, setShowFloatingIndicator } = useScan();
  if (!showFloatingIndicator || activeSection === 'vulnerabilities') return null;
  return (
    <ScanProgressIndicator
      progress={scanProgress}
      onExpand={() => onOpenSection('vulnerabilities')}
      onDismiss={() => setShowFloatingIndicator(false)}
    />
  );
}

const registry: LegacyRegistry = {
  sections: [
    { id: 'dashboard', label: 'Security Dashboard', icon: LayoutDashboard, render: () => <DashboardSection /> },
    { id: 'threats', label: 'Threat Detection', icon: Shield, render: () => <ThreatDetectionSection /> },
    { id: 'network', label: 'Network Security', icon: Network, render: () => <NetworkSecuritySection /> },
    { id: 'vulnerabilities', label: 'Vulnerability Scan', icon: Search, render: () => <VulnerabilitiesSection /> },
    { id: 'ai-analysis', label: 'AI Analysis', icon: Sparkles, render: () => <AIAnalysisSection /> },
    { id: 'reports', label: 'Reports', icon: FileText, render: () => <ReportsSection /> },
  ],
  Provider: ScanProvider,
  Overlay: ScanOverlay,
};

export default registry;
