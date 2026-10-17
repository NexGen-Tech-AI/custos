// AEGIS Custos perf views (default build; src-tauri feature "aegis"), each
// behind the perf DB check.
import { Binary, Cpu, LineChart, Trophy } from 'lucide-react';
import { DeviceSection } from '../components/sections/perf/DeviceSection';
import { RooflineSection } from '../components/sections/perf/RooflineSection';
import { WinnersSection } from '../components/sections/perf/WinnersSection';
import { KernelSection } from '../components/sections/perf/KernelSection';
import { PerfGate } from '../components/sections/perf/PerfGate';
import type { AegisRegistry } from './types';

const gated = (view: JSX.Element) => () => <PerfGate>{view}</PerfGate>;

const registry: AegisRegistry = {
  sections: [
    { id: 'perf-device', label: 'Device (AEGIS)', icon: Cpu, render: gated(<DeviceSection />) },
    { id: 'perf-roofline', label: 'Roofline (AEGIS)', icon: LineChart, render: gated(<RooflineSection />) },
    { id: 'perf-winners', label: 'Winners (AEGIS)', icon: Trophy, render: gated(<WinnersSection />) },
    { id: 'perf-kernel', label: 'Kernel (AEGIS)', icon: Binary, render: gated(<KernelSection />) },
  ],
};

export default registry;
