// The AEGIS Custos perf views plug into the app shell through this interface.
// `@aegis` resolves to ./enabled.tsx (default) or ./disabled.tsx (VITE_AEGIS=0,
// built with the src-tauri feature "aegis" off: the original system monitor).
import type { FC } from 'react';
import type { ExtraSection } from '../legacy/types';

export interface AegisRegistry {
  sections: ExtraSection[];
  /** Shown above every AEGIS section: the perf DB state when it is unusable. */
  Banner: FC;
}
