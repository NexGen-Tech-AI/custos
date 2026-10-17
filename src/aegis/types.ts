// The AEGIS Custos perf views plug into the app shell through this interface.
// `@aegis` resolves to ./enabled.tsx (default) or ./disabled.tsx (VITE_AEGIS=0,
// built with the src-tauri feature "aegis" off: the original system monitor).
import type { ExtraSection } from '../legacy/types';

export interface AegisRegistry {
  /** Each renders behind PerfGate: an unusable perf DB shows only its state. */
  sections: ExtraSection[];
}
