import React from 'react';
import { Activity, Pause, Play } from 'lucide-react';
import { SystemInfo } from '../types';
import { ThemeToggle } from './ThemeToggle';

interface HeaderProps {
  systemInfo: SystemInfo | null;
  isMonitoring: boolean;
  onToggleMonitoring: () => void;
}

export const Header: React.FC<HeaderProps> = ({ systemInfo, isMonitoring, onToggleMonitoring }) => {
  return (
    <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 transition-colors duration-200">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Activity className="w-8 h-8 text-blue-600 dark:text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold">Custos</h1>
              {systemInfo && (
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {systemInfo.hostname} • {systemInfo.os_name} {systemInfo.os_version} • {systemInfo.cpu_brand}
                </p>
              )}
            </div>
          </div>
          
          <div className="flex items-center space-x-3">
            <ThemeToggle />
            
            <button
              onClick={onToggleMonitoring}
              className={`
                flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors
                ${isMonitoring 
                  ? 'bg-red-600 hover:bg-red-700 text-white' 
                  : 'bg-blue-600 hover:bg-blue-700 text-white'
                }
              `}
            >
              {isMonitoring ? (
                <>
                  <Pause className="w-4 h-4" />
                  <span>Pause Monitoring</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Start Monitoring</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};