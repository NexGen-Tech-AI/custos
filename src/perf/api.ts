// invoke() wrappers for the AEGIS Custos perf commands (src-tauri/src/perf.rs).
import { invoke } from '@tauri-apps/api/core';
import type { ArchModel, DbStatus, Device, KernelDetail, PerfSources, Regression, Roofline, WinChain, Winner } from './types';

export const perfApi = {
  status: () => invoke<DbStatus>('perf_status'),
  sources: () => invoke<PerfSources>('perf_sources'),
  devices: () => invoke<Device[]>('devices'),
  archModel: (sm: number) => invoke<ArchModel | null>('arch_model', { sm }),
  roofline: (sm: number) => invoke<Roofline | null>('roofline', { sm }),
  winners: (sm: number) => invoke<Winner[]>('winners', { sm }),
  kernelDetail: (kernelId: string) => invoke<KernelDetail | null>('kernel_detail', { kernelId }),
  winChain: (sm: number, shape: string | null) => invoke<WinChain | null>('win_chain', { sm, shape }),
  regression: (sm: number) => invoke<Regression>('regression', { sm }),
};
