// Real-time Scanning Progress Display (Norton-style)

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Shield, AlertTriangle, CheckCircle2, Loader2, Clock, FileSearch } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface ScanProgress {
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

interface ScanningProgressProps {
  onScanComplete?: () => void;
}

const ScanningProgress: React.FC<ScanningProgressProps> = ({ onScanComplete }) => {
  const [progress, setProgress] = useState<ScanProgress>({
    status: 'idle',
    scan_type: 'quick',
    packages_scanned: 0,
    total_packages: 0,
    vulnerabilities_found: 0,
    critical_threats: 0,
    elapsed_seconds: 0,
  });

  const [showResults, setShowResults] = useState(false);

  const startScan = async (scan_type: 'quick' | 'full') => {
    console.log(`Starting ${scan_type} scan...`);
    setProgress({
      status: 'scanning',
      scan_type,
      packages_scanned: 0,
      total_packages: 0,
      vulnerabilities_found: 0,
      critical_threats: 0,
      elapsed_seconds: 0,
    });
    setShowResults(false);

    try {
      // Start the scan in the background
      if (scan_type === 'quick') {
        await invoke('start_quick_scan');
      } else {
        await invoke('scan_vulnerabilities');
      }
    } catch (error) {
      console.error('Scan failed:', error);
      setProgress(prev => ({ ...prev, status: 'error' }));
    }
  };

  // Poll for progress updates
  useEffect(() => {
    if (progress.status !== 'scanning') return;

    const interval = setInterval(async () => {
      try {
        const scanProgress = await invoke<ScanProgress>('get_scan_progress');
        setProgress(scanProgress);

        if (scanProgress.status === 'complete') {
          setShowResults(true);
          if (onScanComplete) onScanComplete();
        }
      } catch (error) {
        console.error('Failed to get scan progress:', error);
      }
    }, 500); // Update every 500ms

    return () => clearInterval(interval);
  }, [progress.status, onScanComplete]);

  // Calculate progress percentage
  const progressPercent = progress.total_packages > 0
    ? (progress.packages_scanned / progress.total_packages) * 100
    : 0;

  const formatTime = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  };

  return (
    <div className="space-y-6">
      {/* Scan Type Selection */}
      {progress.status === 'idle' && (
        <div className="grid grid-cols-2 gap-4">
          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => startScan('quick')}
            className="rounded-2xl border border-blue-500/30 bg-blue-500/10 p-6 text-left transition-colors hover:bg-blue-500/20"
          >
            <div className="flex items-center gap-3 mb-2">
              <Shield className="h-6 w-6 text-blue-400" />
              <h3 className="text-lg font-semibold text-white">Quick Scan</h3>
            </div>
            <p className="text-sm text-gray-400">Scan critical packages and common vulnerabilities</p>
            <p className="mt-2 text-xs text-blue-300">~2-5 minutes</p>
          </motion.button>

          <motion.button
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            onClick={() => startScan('full')}
            className="rounded-2xl border border-monitor-500/30 bg-monitor-500/10 p-6 text-left transition-colors hover:bg-monitor-500/20"
          >
            <div className="flex items-center gap-3 mb-2">
              <FileSearch className="h-6 w-6 text-monitor-400" />
              <h3 className="text-lg font-semibold text-white">Full Scan</h3>
            </div>
            <p className="text-sm text-gray-400">Deep scan of all installed packages</p>
            <p className="mt-2 text-xs text-monitor-300">~10-30 minutes</p>
          </motion.button>
        </div>
      )}

      {/* Scanning in Progress */}
      <AnimatePresence>
        {progress.status === 'scanning' && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="rounded-2xl border border-monitor-500/30 bg-gradient-to-br from-monitor-600/10 to-purple-600/10 p-8"
          >
            {/* Header */}
            <div className="mb-6 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
                >
                  <Shield className="h-8 w-8 text-monitor-400" />
                </motion.div>
                <div>
                  <h3 className="text-xl font-semibold text-white">
                    {progress.scan_type === 'quick' ? 'Quick Scan' : 'Full System Scan'} in Progress
                  </h3>
                  <p className="text-sm text-gray-400">Analyzing your system for vulnerabilities...</p>
                </div>
              </div>

              <div className="text-right">
                <div className="flex items-center gap-2 text-gray-400">
                  <Clock className="h-4 w-4" />
                  <span className="text-sm">{formatTime(progress.elapsed_seconds)}</span>
                </div>
                {progress.eta_seconds && (
                  <div className="text-xs text-gray-500 mt-1">
                    ETA: {formatTime(progress.eta_seconds)}
                  </div>
                )}
              </div>
            </div>

            {/* Progress Bar */}
            <div className="mb-6">
              <div className="mb-2 flex items-center justify-between text-sm">
                <span className="text-gray-300">
                  {progress.packages_scanned.toLocaleString()} / {progress.total_packages.toLocaleString()} packages scanned
                </span>
                <span className="font-semibold text-monitor-400">{progressPercent.toFixed(1)}%</span>
              </div>
              <div className="h-4 w-full overflow-hidden rounded-full bg-gray-700">
                <motion.div
                  className="h-full bg-gradient-to-r from-monitor-600 to-purple-600"
                  initial={{ width: 0 }}
                  animate={{ width: `${progressPercent}%` }}
                  transition={{ duration: 0.3 }}
                />
              </div>
            </div>

            {/* Current Item */}
            {progress.current_package && (
              <div className="mb-6 rounded-xl border border-gray-700/50 bg-gray-800/50 p-4">
                <div className="flex items-center gap-2 text-sm text-gray-400">
                  <Loader2 className="h-4 w-4 animate-spin text-monitor-400" />
                  <span>Scanning: <span className="font-mono text-white">{progress.current_package}</span></span>
                </div>
              </div>
            )}

            {/* Live Stats */}
            <div className="grid grid-cols-2 gap-4">
              <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm text-gray-400">Vulnerabilities</div>
                    <div className="mt-1 text-3xl font-bold text-red-400">
                      {progress.vulnerabilities_found}
                    </div>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-red-400/50" />
                </div>
              </div>

              <div className="rounded-xl border border-orange-500/30 bg-orange-500/10 p-4">
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-sm text-gray-400">Critical Threats</div>
                    <div className="mt-1 text-3xl font-bold text-orange-400">
                      {progress.critical_threats}
                    </div>
                  </div>
                  <Shield className="h-8 w-8 text-orange-400/50" />
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Scan Complete */}
      <AnimatePresence>
        {showResults && progress.status === 'complete' && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="rounded-2xl border border-green-500/30 bg-green-500/10 p-8 text-center"
          >
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.2, type: 'spring', stiffness: 200 }}
            >
              <CheckCircle2 className="mx-auto h-16 w-16 text-green-400" />
            </motion.div>

            <h3 className="mt-4 text-2xl font-semibold text-white">Scan Complete</h3>
            <p className="mt-2 text-gray-400">
              Scanned {progress.packages_scanned.toLocaleString()} packages in {formatTime(progress.elapsed_seconds)}
            </p>

            <div className="mt-6 grid grid-cols-2 gap-4">
              <div className="rounded-xl bg-red-500/20 p-4">
                <div className="text-3xl font-bold text-red-400">{progress.vulnerabilities_found}</div>
                <div className="text-sm text-gray-300">Vulnerabilities Found</div>
              </div>
              <div className="rounded-xl bg-orange-500/20 p-4">
                <div className="text-3xl font-bold text-orange-400">{progress.critical_threats}</div>
                <div className="text-sm text-gray-300">Critical Threats</div>
              </div>
            </div>

            <button
              onClick={() => setProgress({ ...progress, status: 'idle' })}
              className="mt-6 rounded-xl bg-monitor-600 px-6 py-3 text-white transition-colors hover:bg-monitor-700"
            >
              Run Another Scan
            </button>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error State */}
      {progress.status === 'error' && (
        <div className="rounded-2xl border border-red-500/30 bg-red-500/10 p-8 text-center">
          <AlertTriangle className="mx-auto h-16 w-16 text-red-400" />
          <h3 className="mt-4 text-xl font-semibold text-white">Scan Failed</h3>
          <p className="mt-2 text-gray-400">
            An error occurred during the scan. Please try again.
          </p>
          <button
            onClick={() => setProgress({ ...progress, status: 'idle' })}
            className="mt-6 rounded-xl bg-red-600 px-6 py-3 text-white transition-colors hover:bg-red-700"
          >
            Try Again
          </button>
        </div>
      )}
    </div>
  );
};

export default ScanningProgress;
