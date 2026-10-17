// AEGIS Custos perf views (default build; src-tauri feature "aegis").
import { Binary, Cpu, LineChart, Trophy } from 'lucide-react';
import { DeviceSection } from '../components/sections/perf/DeviceSection';
import { RooflineSection } from '../components/sections/perf/RooflineSection';
import { WinnersSection } from '../components/sections/perf/WinnersSection';
import { KernelSection } from '../components/sections/perf/KernelSection';
import { PerfStatusBanner } from '../components/sections/perf/PerfStatusBanner';
import type { AegisRegistry } from './types';

const registry: AegisRegistry = {
  sections: [
    { id: 'perf-device', label: 'Device (AEGIS)', icon: Cpu, render: () => <DeviceSection /> },
    { id: 'perf-roofline', label: 'Roofline (AEGIS)', icon: LineChart, render: () => <RooflineSection /> },
    { id: 'perf-winners', label: 'Winners (AEGIS)', icon: Trophy, render: () => <WinnersSection /> },
    { id: 'perf-kernel', label: 'Kernel (AEGIS)', icon: Binary, render: () => <KernelSection /> },
  ],
  Banner: PerfStatusBanner,
};

export default registry;
