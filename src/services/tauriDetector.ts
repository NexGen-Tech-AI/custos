// Alternative Tauri detection service for Tauri v2

export async function detectTauriEnvironment(): Promise<boolean> {
  // Method 1: Check for Tauri v2 global API structure
  if (typeof window !== 'undefined' && window.__TAURI__) {
    // In Tauri v2, the structure is window.__TAURI__.core.invoke
    if (window.__TAURI__.core && typeof window.__TAURI__.core.invoke === 'function') {
      return true;
    }

    // Legacy structure check
    if (window.__TAURI__.tauri && typeof window.__TAURI__.tauri.invoke === 'function') {
      return true;
    }

    // Additional Tauri v2 checks
    if (window.__TAURI__.event && typeof window.__TAURI__.event.listen === 'function') {
      return true;
    }
  }

  // Method 2: Try to import Tauri modules
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    // Try a simple command
    await invoke('get_system_info');
    return true;
  } catch {
    // Ignore
  }

  // Method 3: Check for Tauri-specific globals
  const globalAny = globalThis as any;
  if (globalAny.__TAURI__ || globalAny.__TAURI_INVOKE__ || globalAny.__TAURI_INTERNALS__) {
    return true;
  }

  // Method 4: Environment detection
  if (typeof window !== 'undefined') {
    const searchParams = new URLSearchParams(window.location.search);
    if (searchParams.has('__TAURI__')) {
      return true;
    }
  }

  // Method 5: Check for Tauri v2 specific patterns
  if (typeof window !== 'undefined' && window.__TAURI__) {
    // Check if we have any of the core Tauri v2 APIs
    const hasCore = window.__TAURI__.core;
    const hasEvent = window.__TAURI__.event;
    const hasWindow = window.__TAURI__.window;
    const hasApp = window.__TAURI__.app;

    if (hasCore || hasEvent || hasWindow || hasApp) {
      return true;
    }
  }

  return false;
}

export async function getTauriInvoke() {
  // Try Tauri v2 structure first
  if (window.__TAURI__?.core?.invoke) {
    return window.__TAURI__.core.invoke;
  }

  // Try legacy structure
  if (window.__TAURI__?.tauri?.invoke) {
    return window.__TAURI__.tauri.invoke;
  }

  // Try import
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke;
  } catch {
    return null;
  }
}

export async function getTauriListen() {
  // Try Tauri v2 structure
  if (window.__TAURI__?.event?.listen) {
    return window.__TAURI__.event.listen;
  }

  // Try Tauri v2 core structure
  if (window.__TAURI__?.core?.listen) {
    return window.__TAURI__.core.listen;
  }

  // Try import
  try {
    const { listen } = await import('@tauri-apps/api/event');
    return listen;
  } catch {
    return null;
  }
}
