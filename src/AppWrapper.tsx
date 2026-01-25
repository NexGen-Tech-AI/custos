import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Dashboard } from './components/Dashboard';
import { Header } from './components/Header';
import { ThemeProvider } from './contexts/ThemeContext';
import { SystemInfo, SystemMetrics } from './types';

import './App.css';

export default function AppWrapper() {
  console.log('=== AppWrapper component loaded ===');

  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

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

  // Always show something, even if loading
  return (
    <ThemeProvider>
      <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors duration-200">
        {loading ? (
          <div className="flex items-center justify-center h-screen">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
              <p className="text-gray-600 dark:text-gray-400">Loading System Monitor...</p>
              <p className="text-gray-500 dark:text-gray-500 text-sm mt-2">
                System Info: {systemInfo ? '✓' : '⏳'} | Metrics: {metrics ? '✓' : '⏳'}
              </p>
            </div>
          </div>
        ) : (
          <>
            <Header
              systemInfo={systemInfo}
              isMonitoring={isMonitoring}
              onToggleMonitoring={toggleMonitoring}
            />

            {error && (
              <div className="mx-4 mt-4 p-4 bg-red-100 dark:bg-red-900/50 border border-red-300 dark:border-red-700 rounded-lg">
                <p className="text-red-700 dark:text-red-200">{error}</p>
              </div>
            )}

            <main className="container mx-auto px-4 py-8">
              {systemInfo || metrics ? (
                <Dashboard systemInfo={systemInfo} metrics={metrics} />
              ) : (
                <div className="text-center py-12">
                  <p className="text-gray-600 dark:text-gray-400 text-lg">Waiting for system data...</p>
                </div>
              )}
            </main>
          </>
        )}
      </div>
    </ThemeProvider>
  );
}