import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Sidebar } from './components/Sidebar';
import { DashboardSection } from './components/sections/DashboardSection';
import { MonitoringSection } from './components/sections/MonitoringSection';
import { PlaceholderSection } from './components/sections/PlaceholderSection';
import { ThemeProvider } from './contexts/ThemeContext';
import { ThemeToggle } from './components/ThemeToggle';
import { SystemInfo, SystemMetrics } from './types';
import { Shield, Network, Search, Sparkles, FileText, Settings } from 'lucide-react';

import './App.css';

export default function AppWrapper() {
  console.log('=== AppWrapper component loaded ===');

  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeSection, setActiveSection] = useState('dashboard');

  useEffect(() => {
    console.log('AppWrapper useEffect running');
    const init = async () => {
      try {
        console.log('Starting initialization...');
        document.title = 'System Monitor';

        // Load system info
        try {
          console.log('Calling get_system_info...');
          const info = await invoke<SystemInfo>('get_system_info');
          console.log('System info received:', info);
          setSystemInfo(info);
        } catch (err) {
          console.error('Failed to load system info:', err);
          setError(`Failed to load system info: ${err}`);
          setLoading(false);
          return;
        }

        // Start monitoring
        try {
          console.log('Starting monitoring...');
          await invoke('start_monitoring');
          setIsMonitoring(true);
          console.log('Monitoring started successfully');
        } catch (err) {
          console.error('Failed to start monitoring:', err);
          setError(`Failed to start monitoring: ${err}`);
          setLoading(false);
          return;
        }

        // Get initial metrics
        try {
          console.log('Getting initial metrics...');
          const initialMetrics = await invoke<SystemMetrics>('get_current_metrics');
          console.log('Initial metrics received:', initialMetrics);
          if (initialMetrics) {
            setMetrics(initialMetrics);
          }
        } catch (err) {
          console.error('Failed to get initial metrics:', err);
        }

        // Set up polling for metrics
        console.log('Setting up polling for metrics...');
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
        console.log('Initialization completed successfully');

        // Return cleanup function
        return () => {
          console.log('Cleaning up...');
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

  console.log('=== AppWrapper Render ===');
  console.log('Loading:', loading);
  console.log('SystemInfo:', systemInfo ? 'LOADED' : 'NULL', systemInfo);
  console.log('Metrics:', metrics ? 'LOADED' : 'NULL');
  console.log('Error:', error);

  const renderSection = () => {
    switch (activeSection) {
      case 'dashboard':
        return <DashboardSection />;
      case 'monitoring':
        return <MonitoringSection systemInfo={systemInfo} metrics={metrics} />;
      case 'threats':
        return <PlaceholderSection title="Threat Detection" description="Real-time threat detection and analysis powered by AI" icon={Shield} />;
      case 'network':
        return <PlaceholderSection title="Network Security" description="Monitor and secure your network connections" icon={Network} />;
      case 'vulnerabilities':
        return <PlaceholderSection title="Vulnerability Scanner" description="Identify and assess system vulnerabilities" icon={Search} />;
      case 'ai-analysis':
        return <PlaceholderSection title="AI Analysis" description="Advanced AI-powered security analysis and insights" icon={Sparkles} />;
      case 'reports':
        return <PlaceholderSection title="Security Reports" description="Generate comprehensive security reports" icon={FileText} />;
      case 'settings':
        return <PlaceholderSection title="Settings" description="Configure your security preferences" icon={Settings} comingSoon={false} />;
      default:
        return <DashboardSection />;
    }
  };

  // Always show something, even if loading
  return (
    <ThemeProvider>
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
      </div>
    </ThemeProvider>
  );
}