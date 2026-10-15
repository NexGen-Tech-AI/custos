/// <reference types="vite/client" />

type TauriGlobalInvoke = <T = unknown>(cmd: string, args?: Record<string, unknown>) => Promise<T>;
type TauriGlobalListen = (event: string, handler: (payload: unknown) => void) => Promise<() => void>;

// Tauri injects this global (tauri.conf.json: app.withGlobalTauri = true).
// services/tauriDetector.ts probes several layouts (v2 namespaces, and the
// v1 `tauri` one), so every member is optional.
interface Window {
  __TAURI__?: {
    core?: { invoke?: TauriGlobalInvoke; listen?: TauriGlobalListen };
    event?: { listen?: TauriGlobalListen };
    tauri?: { invoke?: TauriGlobalInvoke };
    window?: unknown;
    app?: unknown;
  };
}
