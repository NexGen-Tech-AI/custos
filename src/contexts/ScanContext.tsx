// Scan Context - Share scan progress state across all components
// Enables picture-in-picture scan indicator to work across navigation

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { invoke } from '@tauri-apps/api/core';

export interface ScanProgress {
  status: 'idle' | 'scanning' | 'complete' | 'error';
  scan_type: 'quick' | 'full';
  packages_scanned: number;
  total_packages: number;
  vulnerabilities_found: number;
  critical_threats: number;
  elapsed_seconds: number;
  current_package?: string;
  eta_seconds?: number;
}

interface ScanContextType {
  scanProgress: ScanProgress;
  setScanProgress: React.Dispatch<React.SetStateAction<ScanProgress>>;
  startScan: (scanType: 'quick' | 'full') => Promise<void>;
  showFloatingIndicator: boolean;
  setShowFloatingIndicator: React.Dispatch<React.SetStateAction<boolean>>;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const useScan = () => {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
};

interface ScanProviderProps {
  children: ReactNode;
}

export const ScanProvider: React.FC<ScanProviderProps> = ({ children }) => {
  const [scanProgress, setScanProgress] = useState<ScanProgress>({
    status: 'idle',
    scan_type: 'quick',
    packages_scanned: 0,
    total_packages: 0,
    vulnerabilities_found: 0,
    critical_threats: 0,
    elapsed_seconds: 0,
  });

  const [showFloatingIndicator, setShowFloatingIndicator] = useState(true);

  // Poll for scan progress when scanning
  useEffect(() => {
    if (scanProgress.status !== 'scanning') return;

    const interval = setInterval(async () => {
      try {
        const progress = await invoke<ScanProgress>('get_scan_progress');
        setScanProgress(progress);
      } catch (error) {
        console.error('Failed to get scan progress:', error);
      }
    }, 500); // Poll every 500ms

    return () => clearInterval(interval);
  }, [scanProgress.status]);

  const startScan = async (scanType: 'quick' | 'full') => {
    console.log(`Starting ${scanType} scan from global context...`);

    setScanProgress({
      status: 'scanning',
      scan_type: scanType,
      packages_scanned: 0,
      total_packages: 0,
      vulnerabilities_found: 0,
      critical_threats: 0,
      elapsed_seconds: 0,
    });

    setShowFloatingIndicator(true);

    try {
      if (scanType === 'quick') {
        await invoke('start_quick_scan');
      } else {
        await invoke('scan_vulnerabilities');
      }
    } catch (error) {
      console.error('Scan failed:', error);
      setScanProgress(prev => ({ ...prev, status: 'error' }));
    }
  };

  const value = {
    scanProgress,
    setScanProgress,
    startScan,
    showFloatingIndicator,
    setShowFloatingIndicator,
  };

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
};
