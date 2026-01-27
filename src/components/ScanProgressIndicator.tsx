// Floating Picture-in-Picture Scan Progress Indicator
// Stays visible when navigating away from scan page

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Loader2, X, Maximize2 } from 'lucide-react';

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

interface ScanProgressIndicatorProps {
  progress: ScanProgress;
  onExpand: () => void;
  onDismiss: () => void;
}

const ScanProgressIndicator: React.FC<ScanProgressIndicatorProps> = ({
  progress,
  onExpand,
  onDismiss,
}) => {
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
    <AnimatePresence>
      {progress.status === 'scanning' && (
        <motion.div
          initial={{ opacity: 0, y: 100, scale: 0.8 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 100, scale: 0.8 }}
          transition={{ type: 'spring', stiffness: 300, damping: 30 }}
          className="fixed bottom-6 left-6 z-50 w-96 cursor-pointer"
        >
          {/* Main container */}
          <div
            onClick={onExpand}
            className="rounded-2xl border border-monitor-500/30 bg-gray-900/95 backdrop-blur-xl shadow-2xl transition-all hover:shadow-monitor-500/20"
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-gray-700/50 px-4 py-3">
              <div className="flex items-center gap-2">
                <motion.div
                  animate={{ rotate: 360 }}
                  transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
                >
                  <Shield className="h-5 w-5 text-monitor-400" />
                </motion.div>
                <div>
                  <div className="text-sm font-semibold text-white">
                    {progress.scan_type === 'quick' ? 'Quick Scan' : 'Full Scan'}
                  </div>
                  <div className="text-xs text-gray-400">
                    {formatTime(progress.elapsed_seconds)}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-1">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onExpand();
                  }}
                  className="rounded-lg p-1.5 text-gray-400 transition-colors hover:bg-gray-700/50 hover:text-white"
                  title="Expand"
                >
                  <Maximize2 className="h-4 w-4" />
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onDismiss();
                  }}
                  className="rounded-lg p-1.5 text-gray-400 transition-colors hover:bg-gray-700/50 hover:text-red-400"
                  title="Minimize"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* Progress content */}
            <div className="p-4">
              {/* Progress bar */}
              <div className="mb-3">
                <div className="mb-1.5 flex items-center justify-between text-xs">
                  <span className="text-gray-300">
                    {progress.packages_scanned.toLocaleString()} / {progress.total_packages.toLocaleString()} packages
                  </span>
                  <span className="font-semibold text-monitor-400">
                    {progressPercent.toFixed(0)}%
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-gray-700">
                  <motion.div
                    className="h-full bg-gradient-to-r from-monitor-600 to-purple-600"
                    initial={{ width: 0 }}
                    animate={{ width: `${progressPercent}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
              </div>

              {/* Current package */}
              {progress.current_package && (
                <div className="mb-3 flex items-center gap-2 rounded-lg border border-gray-700/50 bg-gray-800/50 px-3 py-2">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-monitor-400 flex-shrink-0" />
                  <span className="truncate font-mono text-xs text-gray-300">
                    {progress.current_package}
                  </span>
                </div>
              )}

              {/* Stats */}
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2">
                  <div className="text-xs text-gray-400">Vulnerabilities</div>
                  <div className="text-xl font-bold text-red-400">
                    {progress.vulnerabilities_found}
                  </div>
                </div>
                <div className="rounded-lg border border-orange-500/20 bg-orange-500/10 px-3 py-2">
                  <div className="text-xs text-gray-400">Critical</div>
                  <div className="text-xl font-bold text-orange-400">
                    {progress.critical_threats}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
};

export default ScanProgressIndicator;
