// Connection Explorer - Advanced filtering and timeline view

import React from 'react';
import { Search, Filter, Calendar } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

const ConnectionExplorer: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Coming Soon Banner */}
      <div className="rounded-2xl border border-monitor-500/20 bg-monitor-500/5 p-8 text-center">
        <Search className="mx-auto h-16 w-16 text-monitor-400" />
        <h3 className="mt-4 text-xl font-semibold text-white">Connection Explorer</h3>
        <p className="mt-2 text-gray-400">
          Advanced filtering, timeline view, and story mode for connection analysis
        </p>
        <Badge className="mt-4 rounded-full bg-monitor-600/20 text-monitor-300">
          Coming Soon
        </Badge>
      </div>

      {/* Feature Preview */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <FeatureCard
          icon={Filter}
          title="Advanced Filters"
          description="Filter by device, port, protocol, country/ASN, and time window"
        />
        <FeatureCard
          icon={Calendar}
          title="Timeline View"
          description="Visualize connections over time with interactive timeline"
        />
        <FeatureCard
          icon={Search}
          title="Story Mode"
          description="'This host started doing X at time Y after process Z executed'"
        />
      </div>
    </div>
  );
};

interface FeatureCardProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
}

const FeatureCard: React.FC<FeatureCardProps> = ({ icon: Icon, title, description }) => {
  return (
    <div className="rounded-xl border border-gray-700 bg-gray-800/30 p-6">
      <Icon className="h-8 w-8 text-monitor-400" />
      <h4 className="mt-3 font-semibold text-white">{title}</h4>
      <p className="mt-2 text-sm text-gray-400">{description}</p>
    </div>
  );
};

export default ConnectionExplorer;
