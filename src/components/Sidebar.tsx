import React from 'react';
import {
  LayoutDashboard,
  Activity,
  Shield,
  Network,
  Search,
  Sparkles,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import logo from '../assets/logo.png';

interface SidebarProps {
  isCollapsed: boolean;
  onToggle: () => void;
  activeSection: string;
  onSectionChange: (section: string) => void;
}

const menuItems = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'monitoring', label: 'System Monitoring', icon: Activity },
  { id: 'threats', label: 'Threat Detection', icon: Shield },
  { id: 'network', label: 'Network Security', icon: Network },
  { id: 'vulnerabilities', label: 'Vulnerability Scan', icon: Search },
  { id: 'ai-analysis', label: 'AI Analysis', icon: Sparkles },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export const Sidebar: React.FC<SidebarProps> = ({
  isCollapsed,
  onToggle,
  activeSection,
  onSectionChange
}) => {
  return (
    <aside
      className={`
        ${isCollapsed ? 'w-20' : 'w-64'}
        bg-white dark:bg-gray-800
        border-r border-gray-200 dark:border-gray-700
        transition-all duration-300 ease-in-out
        flex flex-col
        h-screen
        sticky top-0
      `}
    >
      {/* Logo and Brand */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <img
              src={logo}
              alt="Custos Logo"
              className="w-10 h-10 rounded-lg"
            />
            {!isCollapsed && (
              <div>
                <h1 className="text-xl font-bold text-blue-600 dark:text-blue-400">Custos</h1>
                <p className="text-xs text-gray-500 dark:text-gray-400">AI-Powered Security</p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4">
        <ul className="space-y-1 px-2">
          {menuItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeSection === item.id;

            return (
              <li key={item.id}>
                <button
                  onClick={() => onSectionChange(item.id)}
                  className={`
                    w-full flex items-center space-x-3 px-3 py-3 rounded-lg
                    transition-all duration-200
                    ${isActive
                      ? 'bg-blue-50 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                      : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                    }
                    ${isCollapsed ? 'justify-center' : ''}
                  `}
                  title={isCollapsed ? item.label : ''}
                >
                  <Icon className={`w-5 h-5 ${isActive ? 'text-blue-600 dark:text-blue-400' : ''}`} />
                  {!isCollapsed && (
                    <span className="text-sm font-medium">{item.label}</span>
                  )}
                  {!isCollapsed && isActive && (
                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-blue-600 dark:bg-blue-400"></div>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Toggle Button */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700">
        <button
          onClick={onToggle}
          className="
            w-full flex items-center justify-center
            px-3 py-2 rounded-lg
            bg-gray-100 dark:bg-gray-700
            hover:bg-gray-200 dark:hover:bg-gray-600
            transition-colors duration-200
          "
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? (
            <ChevronRight className="w-5 h-5 text-gray-600 dark:text-gray-300" />
          ) : (
            <>
              <ChevronLeft className="w-5 h-5 text-gray-600 dark:text-gray-300" />
              <span className="ml-2 text-sm text-gray-600 dark:text-gray-300">Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  );
};
