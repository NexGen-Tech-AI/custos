import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Sidebar } from './components/Sidebar';
import { DashboardSection } from './components/sections/DashboardSection';
import { MonitoringSection } from './components/sections/MonitoringSection';
import { PlaceholderSection } from './components/sections/PlaceholderSection';
import ThreatDetectionSection from './components/sections/ThreatDetectionSection';
import NetworkSecuritySection from './components/sections/network-security/NetworkSecuritySection';
import VulnerabilitiesSection from './components/sections/vulnerabilities/VulnerabilitiesSection';
import AIAnalysisSection from './components/AIAnalysisSection';
import ReportsSection from './components/sections/ReportsSection';
import { ThemeProvider } from './contexts/ThemeContext';
import { ScanProvider, useScan } from './contexts/ScanContext';
import { ThemeToggle } from './components/ThemeToggle';
import ScanProgressIndicator from './components/ScanProgressIndicator';
import { SystemInfo, SystemMetrics } from './types';
import { Shield, Network, Search, Sparkles, FileText, Settings } from 'lucide-react';

import './App.css';

// Main App Content (uses context)
function App() {
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeSection, setActiveSection] = useState('dashboard');

  // Use scan context instead of local state
  const { scanProgress, showFloatingIndicator, setShowFloatingIndicator } = useScan();

  useEffect(() => {
    const init = async () => {
      try {
        document.title = 'System Monitor';

        // Load system info
        try {
          const info = await invoke<SystemInfo>('get_system_info');
          setSystemInfo(info);
        } catch (err) {
          console.error('Failed to load system info:', err);
          setError(`Failed to load system info: ${err}`);
          setLoading(false);
          return;
        }

        // Start monitoring
        try {
          await invoke('start_monitoring');
          setIsMonitoring(true);
        } catch (err) {
          console.error('Failed to start monitoring:', err);
          setError(`Failed to start monitoring: ${err}`);
          setLoading(false);
          return;
        }

        // Get initial metrics
        try {
          const initialMetrics = await invoke<SystemMetrics>('get_current_metrics');
          if (initialMetrics) {
            setMetrics(initialMetrics);
          }
        } catch (err) {
          console.error('Failed to get initial metrics:', err);
        }

        // Set up polling for metrics
        const pollInterval = setInterval(async () => {
          try {
            const currentMetrics = await invoke<SystemMetrics>('get_current_metrics');
            if (currentMetrics) {
              setMetrics(currentMetrics);
            }
          } catch (err) {
            console.error('Polling failed:', err);
          }
        }, 3000); // Poll every 3 seconds

        setLoading(false);

        // Return cleanup function
        return () => {
          clearInterval(pollInterval);
          invoke('stop_monitoring').catch(console.error);
        };
      } catch (err) {
        console.error('Initialization error:', err);
        setError(`Initialization error: ${err}`);
        setLoading(false);
      }
    };

    init();
  }, []);

  const handleExpandScan = () => {
    setActiveSection('vulnerabilities');
  };

  const handleDismissScan = () => {
    setShowFloatingIndicator(false);
  };

  const toggleMonitoring = async () => {
    try {
      if (isMonitoring) {
        await invoke('stop_monitoring');
        setIsMonitoring(false);
      } else {
        await invoke('start_monitoring');
        setIsMonitoring(true);
      }
    } catch (err) {
      console.error('Failed to toggle monitoring:', err);
      setError(`Failed to toggle monitoring: ${err}`);
    }
  };

  const renderSection = () => {
    switch (activeSection) {
      case 'dashboard':
        return <DashboardSection />;
      case 'monitoring':
        return <MonitoringSection systemInfo={systemInfo} metrics={metrics} />;
      case 'threats':
        return <ThreatDetectionSection />;
      case 'network':
        return <NetworkSecuritySection />;
      case 'vulnerabilities':
        return <VulnerabilitiesSection />;
      case 'ai-analysis':
        return <AIAnalysisSection />;
      case 'reports':
        return <ReportsSection />;
      case 'settings':
        return <PlaceholderSection title="Settings" description="Configure your security preferences" icon={Settings} comingSoon={false} />;
      default:
        return <DashboardSection />;
    }
  };

  // Always show something, even if loading
  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors duration-200">
        {loading ? (
          <div className="flex items-center justify-center h-screen">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
              <p className="text-gray-600 dark:text-gray-400">Loading Custos...</p>
              <p className="text-gray-500 dark:text-gray-500 text-sm mt-2">
                System Info: {systemInfo ? '✓' : '⏳'} | Metrics: {metrics ? '✓' : '⏳'}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex h-screen">
            <Sidebar
              isCollapsed={sidebarCollapsed}
              onToggle={() => setSidebarCollapsed(!sidebarCollapsed)}
              activeSection={activeSection}
              onSectionChange={setActiveSection}
            />

            <div className="flex-1 flex flex-col overflow-hidden">
              {/* Top bar */}
              <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4">
                <div className="flex items-center justify-between">
                  <div>
                    {systemInfo && (
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        {systemInfo.hostname} • {systemInfo.os_name} {systemInfo.os_version}
                      </p>
                    )}
                  </div>
                  <div className="flex items-center space-x-4">
                    {activeSection === 'monitoring' && (
                      <button
                        onClick={toggleMonitoring}
                        className={`
                          flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors text-sm
                          ${isMonitoring
                            ? 'bg-red-600 hover:bg-red-700 text-white'
                            : 'bg-blue-600 hover:bg-blue-700 text-white'
                          }
                        `}
                      >
                        <span>{isMonitoring ? 'Pause Monitoring' : 'Start Monitoring'}</span>
                      </button>
                    )}
                    <ThemeToggle />
                  </div>
                </div>
              </header>

              {/* Main content */}
              <main className="flex-1 overflow-y-auto p-6">
                {error && (
                  <div className="mb-6 p-4 bg-red-100 dark:bg-red-900/50 border border-red-300 dark:border-red-700 rounded-lg">
                    <p className="text-red-700 dark:text-red-200">{error}</p>
                  </div>
                )}

                {renderSection()}
              </main>
            </div>
          </div>
        )}

      {/* Floating scan progress indicator */}
      {showFloatingIndicator && activeSection !== 'vulnerabilities' && (
        <ScanProgressIndicator
          progress={scanProgress}
          onExpand={handleExpandScan}
          onDismiss={handleDismissScan}
        />
      )}
    </div>
  );
}

// Wrapper component that provides context
export default function AppWrapper() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <App />
      </ScanProvider>
    </ThemeProvider>
  );
}