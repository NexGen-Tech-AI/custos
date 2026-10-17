// AEGIS Custos perf views (default build; src-tauri feature "aegis").
import { Cpu, LineChart } from 'lucide-react';
import { DeviceSection } from '../components/sections/perf/DeviceSection';
import { RooflineSection } from '../components/sections/perf/RooflineSection';
import { PerfStatusBanner } from '../components/sections/perf/PerfStatusBanner';
import type { AegisRegistry } from './types';

const registry: AegisRegistry = {
  sections: [
    { id: 'perf-device', label: 'Device (AEGIS)', icon: Cpu, render: () => <DeviceSection /> },
    { id: 'perf-roofline', label: 'Roofline (AEGIS)', icon: LineChart, render: () => <RooflineSection /> },
  ],
  Banner: PerfStatusBanner,
};

export default registry;
