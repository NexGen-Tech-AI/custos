import React from 'react';
import { LucideIcon } from 'lucide-react';

interface PlaceholderSectionProps {
  title: string;
  description: string;
  icon: LucideIcon;
  comingSoon?: boolean;
}

export const PlaceholderSection: React.FC<PlaceholderSectionProps> = ({
  title,
  description,
  icon: Icon,
  comingSoon = true
}) => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-3xl font-bold text-gray-900 dark:text-gray-100">{title}</h2>
        <p className="text-gray-600 dark:text-gray-400 mt-2">{description}</p>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-12">
        <div className="text-center max-w-md mx-auto">
          <div className="bg-blue-50 dark:bg-blue-900/20 w-20 h-20 rounded-full flex items-center justify-center mx-auto mb-6">
            <Icon className="w-10 h-10 text-blue-600 dark:text-blue-400" />
          </div>
          <h3 className="text-2xl font-semibold text-gray-900 dark:text-gray-100 mb-3">{title}</h3>
          <p className="text-gray-600 dark:text-gray-400 mb-6">{description}</p>
          {comingSoon && (
            <div className="inline-flex items-center px-4 py-2 bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 rounded-full text-sm font-medium">
              Coming Soon - AI-Powered Security Features
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
