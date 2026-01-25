import React, { useState, useCallback } from 'react';
import { DndContext, closestCenter, KeyboardSensor, PointerSensor, useSensor, useSensors, DragEndEvent } from '@dnd-kit/core';
import { arrayMove, SortableContext, sortableKeyboardCoordinates, rectSortingStrategy } from '@dnd-kit/sortable';
import { SortableWidget } from './SortableWidget';
import { SystemInfo, SystemMetrics } from '../types';
import { CpuMonitor } from './monitors/CpuMonitor';
import { MemoryMonitor } from './monitors/MemoryMonitor';
import { DiskMonitor } from './monitors/DiskMonitor';
import { NetworkMonitor } from './monitors/NetworkMonitor';
import { ProcessList } from './monitors/ProcessList';
import { GpuMonitor } from './monitors/GpuMonitor';
import KernelMonitor from './monitors/KernelMonitor';
import DpuMonitor from './monitors/DpuMonitor';
import NpuMonitor from './monitors/NpuMonitor';
import FpgaMonitor from './monitors/FpgaMonitor';
import QuantumProcessorMonitor from './monitors/QuantumProcessorMonitor';
import { SystemOverview } from './SystemOverview';
import { GripVertical, Settings } from 'lucide-react';

interface DraggableDashboardProps {
  systemInfo: SystemInfo | null;
  metrics: SystemMetrics | null;
}

interface WidgetConfig {
  id: string;
  title: string;
  component: React.ComponentType<any>;
  props: any;
  size: 'small' | 'medium' | 'large' | 'full';
  visible: boolean;
}

const GRID_COLS = {
  small: 'col-span-12 md:col-span-6 lg:col-span-3',
  medium: 'col-span-12 md:col-span-6',
  large: 'col-span-12 lg:col-span-8',
  full: 'col-span-12'
};

export const DraggableDashboard: React.FC<DraggableDashboardProps> = ({ systemInfo, metrics }) => {
  const [editMode, setEditMode] = useState(false);
  const [widgets, setWidgets] = useState<WidgetConfig[]>(() => {
    // Load saved layout from localStorage
    try {
      const savedLayout = localStorage.getItem('dashboardLayout');
      if (savedLayout) {
        const parsed = JSON.parse(savedLayout);
        // Validate that it's an array
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      }
    } catch (error) {
      console.error('Failed to load dashboard layout:', error);
      // Clear invalid data
      localStorage.removeItem('dashboardLayout');
    }

    // Default layout
    return [
      {
        id: 'overview',
        title: 'System Overview',
        component: SystemOverview,
        props: { systemInfo },
        size: 'full',
        visible: true
      },
      {
        id: 'cpu',
        title: 'CPU Monitor',
        component: CpuMonitor,
        props: { metrics: metrics?.cpu },
        size: 'medium',
        visible: true
      },
      {
        id: 'memory',
        title: 'Memory Monitor',
        component: MemoryMonitor,
        props: { metrics: metrics?.memory },
        size: 'medium',
        visible: true
      },
      {
        id: 'gpu',
        title: 'GPU Monitor',
        component: GpuMonitor,
        props: { gpus: metrics?.gpus },
        size: 'medium',
        visible: true
      },
      {
        id: 'kernel',
        title: 'Kernel Monitor',
        component: KernelMonitor,
        props: {},
        size: 'medium',
        visible: true
      },
      {
        id: 'disk',
        title: 'Disk Monitor',
        component: DiskMonitor,
        props: { disks: metrics?.disks },
        size: 'medium',
        visible: true
      },
      {
        id: 'network',
        title: 'Network Monitor',
        component: NetworkMonitor,
        props: { networks: metrics?.networks },
        size: 'medium',
        visible: true
      },
      {
        id: 'processes',
        title: 'Process List',
        component: ProcessList,
        props: { processes: metrics?.top_processes },
        size: 'full',
        visible: true
      },
      {
        id: 'dpu',
        title: 'DPU Monitor',
        component: DpuMonitor,
        props: { dpus: metrics?.dpus || [] },
        size: 'medium',
        visible: true
      },
      {
        id: 'npu',
        title: 'NPU Monitor',
        component: NpuMonitor,
        props: { npus: metrics?.npus || [] },
        size: 'medium',
        visible: true
      },
      {
        id: 'fpga',
        title: 'FPGA Monitor',
        component: FpgaMonitor,
        props: { fpgas: metrics?.fpgas || [] },
        size: 'medium',
        visible: true
      },
      {
        id: 'quantum',
        title: 'Quantum Processor Monitor',
        component: QuantumProcessorMonitor,
        props: { quantumProcessors: metrics?.quantum_processors || [] },
        size: 'medium',
        visible: true
      }
    ];
  });

  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
    useSensor(KeyboardSensor, {
      coordinateGetter: sortableKeyboardCoordinates,
    })
  );

  const handleDragEnd = useCallback((event: DragEndEvent) => {
    const { active, over } = event;
    
    if (over && active.id !== over.id) {
      setWidgets((items) => {
        const oldIndex = items.findIndex((item) => item.id === active.id);
        const newIndex = items.findIndex((item) => item.id === over.id);
        
        const newItems = arrayMove(items, oldIndex, newIndex);
        
        // Save to localStorage
        localStorage.setItem('dashboardLayout', JSON.stringify(newItems));
        
        return newItems;
      });
    }
  }, []);

  const toggleWidgetVisibility = useCallback((widgetId: string) => {
    setWidgets((items) => {
      const newItems = items.map((item) =>
        item.id === widgetId ? { ...item, visible: !item.visible } : item
      );
      
      localStorage.setItem('dashboardLayout', JSON.stringify(newItems));
      return newItems;
    });
  }, []);

  const changeWidgetSize = useCallback((widgetId: string, size: WidgetConfig['size']) => {
    setWidgets((items) => {
      const newItems = items.map((item) =>
        item.id === widgetId ? { ...item, size } : item
      );
      
      localStorage.setItem('dashboardLayout', JSON.stringify(newItems));
      return newItems;
    });
  }, []);

  // Update widget props when metrics change
  const updatedWidgets = widgets.map((widget) => {
    switch (widget.id) {
      case 'overview':
        return { ...widget, props: { systemInfo } };
      case 'cpu':
        return { ...widget, props: { metrics: metrics?.cpu } };
      case 'memory':
        return { ...widget, props: { metrics: metrics?.memory } };
      case 'gpu':
        return { ...widget, props: { gpus: metrics?.gpus } };
      case 'kernel':
        return { ...widget, props: {} };
      case 'disk':
        return { ...widget, props: { disks: metrics?.disks } };
      case 'network':
        return { ...widget, props: { networks: metrics?.networks } };
      case 'processes':
        return { ...widget, props: { processes: metrics?.top_processes } };
      case 'dpu':
        return { ...widget, props: { dpus: metrics?.dpus || [] } };
      case 'npu':
        return { ...widget, props: { npus: metrics?.npus || [] } };
      case 'fpga':
        return { ...widget, props: { fpgas: metrics?.fpgas || [] } };
      case 'quantum':
        return { ...widget, props: { quantumProcessors: metrics?.quantum_processors || [] } };
      default:
        return widget;
    }
  });

  const visibleWidgets = updatedWidgets.filter((widget) => widget.visible);

  if (!systemInfo && !metrics) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 dark:border-blue-400 mx-auto mb-4"></div>
          <p className="text-gray-600 dark:text-gray-400">Initializing system monitoring...</p>
          <p className="text-sm text-gray-500 dark:text-gray-500 mt-2">
            System Info: {systemInfo ? '✓' : '⏳'} | Metrics: {metrics ? '✓' : '⏳'}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Edit Mode Toggle */}
      <div className="flex justify-end mb-4">
        <button
          onClick={() => setEditMode(!editMode)}
          className={`
            flex items-center space-x-2 px-4 py-2 rounded-lg font-medium transition-colors
            ${editMode 
              ? 'bg-blue-600 text-white' 
              : 'bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-300 dark:hover:bg-gray-600'
            }
          `}
        >
          <Settings className="w-4 h-4" />
          <span>{editMode ? 'Done' : 'Customize Dashboard'}</span>
        </button>
      </div>

      {/* Widget Configuration Panel */}
      {editMode && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow-lg border border-gray-200 dark:border-gray-700 mb-6">
          <h3 className="text-lg font-semibold mb-4">Widget Configuration</h3>
          <div className="space-y-2">
            {updatedWidgets.map((widget) => (
              <div key={widget.id} className="flex items-center justify-between p-2 rounded hover:bg-gray-100 dark:hover:bg-gray-700">
                <div className="flex items-center space-x-3">
                  <GripVertical className="w-4 h-4 text-gray-400" />
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={widget.visible}
                      onChange={() => toggleWidgetVisibility(widget.id)}
                      className="rounded border-gray-300 dark:border-gray-600"
                    />
                    <span>{widget.title}</span>
                  </label>
                </div>
                <select
                  value={widget.size}
                  onChange={(e) => changeWidgetSize(widget.id, e.target.value as WidgetConfig['size'])}
                  className="text-sm px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700"
                  disabled={!widget.visible}
                >
                  <option value="small">Small</option>
                  <option value="medium">Medium</option>
                  <option value="large">Large</option>
                  <option value="full">Full Width</option>
                </select>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Dashboard Grid */}
      <DndContext
        sensors={sensors}
        collisionDetection={closestCenter}
        onDragEnd={handleDragEnd}
      >
        <SortableContext
          items={visibleWidgets.map(w => w.id)}
          strategy={rectSortingStrategy}
        >
          <div className="grid grid-cols-12 gap-4">
            {visibleWidgets.map((widget) => (
              <div key={widget.id} className={GRID_COLS[widget.size]}>
                <SortableWidget
                  id={widget.id}
                  isDraggable={editMode}
                >
                  <widget.component {...widget.props} />
                </SortableWidget>
              </div>
            ))}
          </div>
        </SortableContext>
      </DndContext>
    </div>
  );
};