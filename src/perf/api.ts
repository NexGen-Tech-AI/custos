// invoke() wrappers for the AEGIS Custos perf commands (src-tauri/src/perf.rs).
import { invoke } from '@tauri-apps/api/core';
import type { ArchModel, Device, PerfSources, Roofline } from './types';

export const perfApi = {
  sources: () => invoke<PerfSources>('perf_sources'),
  devices: () => invoke<Device[]>('devices'),
  archModel: (sm: number) => invoke<ArchModel | null>('arch_model', { sm }),
  roofline: (sm: number) => invoke<Roofline | null>('roofline', { sm }),
};
