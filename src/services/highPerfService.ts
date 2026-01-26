// Conditional imports for Tauri API
let invoke: any;
let listen: any;

try {
  const tauriApi = require('@tauri-apps/api/tauri');
  const eventApi = require('@tauri-apps/api/event');
  invoke = tauriApi.invoke;
  listen = eventApi.listen;
} catch (error) {
  invoke = async () => null;
  listen = async () => () => {};
}
import { HighPerfMetrics } from '../types';

export class HighPerfMonitoringService {
  private isRunning = false;
  private metricsCallback?: (metrics: HighPerfMetrics) => void;
  private unsubscribe?: () => void;

  constructor() {
    this.setupEventListeners();
  }

  private async setupEventListeners() {
    try {
      this.unsubscribe = await listen('high-perf-metrics', (event: any) => {
        if (this.metricsCallback && event.payload) {
          try {
            // Decode binary data (assuming it's base64 encoded from Rust)
            const binaryData = atob(event.payload as string);
            const uint8Array = new Uint8Array(binaryData.length);
            for (let i = 0; i < binaryData.length; i++) {
              uint8Array[i] = binaryData.charCodeAt(i);
            }
            
            // For now, we'll use JSON as fallback until we implement proper binary decoding
            // In a real implementation, you'd use a binary decoder like protobuf or flatbuffers
            const metrics = event.payload as HighPerfMetrics;
            this.metricsCallback(metrics);
          } catch (error) {
            console.error('Error processing high-performance metrics:', error);
          }
        }
      });
    } catch (error) {
      console.error('Error setting up high-performance metrics listener:', error);
    }
  }

  public async startMonitoring(callback: (metrics: HighPerfMetrics) => void) {
    if (this.isRunning) {
      return;
    }

    this.metricsCallback = callback;
    
    try {
      await invoke('start_high_perf_monitoring');
      this.isRunning = true;
    } catch (error) {
      console.error('Error starting high-performance monitoring:', error);
      throw error;
    }
  }

  public async stopMonitoring() {
    if (!this.isRunning) {
      return;
    }

    try {
      await invoke('stop_monitoring');
      this.isRunning = false;
      this.metricsCallback = undefined;
    } catch (error) {
      console.error('Error stopping high-performance monitoring:', error);
    }
  }

  public async getLatestMetrics(): Promise<HighPerfMetrics | null> {
    try {
      const metrics = await invoke('get_high_perf_metrics') as HighPerfMetrics | null;
      return metrics;
    } catch (error) {
      console.error('Error getting high-performance metrics:', error);
      return null;
    }
  }

  public isActive(): boolean {
    return this.isRunning;
  }

  public destroy() {
    this.stopMonitoring();
    if (this.unsubscribe) {
      this.unsubscribe();
    }
  }
}

// Performance monitoring utilities
export class PerformanceMonitor {
  private static instance: PerformanceMonitor;
  private metrics: Map<string, number[]> = new Map();
  private maxHistory = 1000;

  private constructor() {}

  public static getInstance(): PerformanceMonitor {
    if (!PerformanceMonitor.instance) {
      PerformanceMonitor.instance = new PerformanceMonitor();
    }
    return PerformanceMonitor.instance;
  }

  public startTimer(name: string): () => void {
    const start = performance.now();
    return () => {
      const duration = performance.now() - start;
      this.recordMetric(name, duration);
    };
  }

  public recordMetric(name: string, value: number) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    
    const history = this.metrics.get(name)!;
    history.push(value);
    
    if (history.length > this.maxHistory) {
      history.shift();
    }
  }

  public getAverage(name: string): number {
    const history = this.metrics.get(name);
    if (!history || history.length === 0) {
      return 0;
    }
    
    const sum = history.reduce((acc, val) => acc + val, 0);
    return sum / history.length;
  }

  public getMin(name: string): number {
    const history = this.metrics.get(name);
    if (!history || history.length === 0) {
      return 0;
    }
    return Math.min(...history);
  }

  public getMax(name: string): number {
    const history = this.metrics.get(name);
    if (!history || history.length === 0) {
      return 0;
    }
    return Math.max(...history);
  }

  public getMetrics(): Map<string, { avg: number; min: number; max: number; count: number }> {
    const result = new Map();
    
    for (const [name, history] of this.metrics) {
      if (history.length > 0) {
        result.set(name, {
          avg: this.getAverage(name),
          min: this.getMin(name),
          max: this.getMax(name),
          count: history.length
        });
      }
    }
    
    return result;
  }

  public clear() {
    this.metrics.clear();
  }
}

// High-performance data structures
export class CircularBuffer<T> {
  private buffer: T[];
  private head = 0;
  private tail = 0;
  private size = 0;
  private capacity: number;

  constructor(capacity: number) {
    this.capacity = capacity;
    this.buffer = new Array(capacity);
  }

  public push(item: T): boolean {
    if (this.size >= this.capacity) {
      return false; // Buffer full
    }
    
    this.buffer[this.head] = item;
    this.head = (this.head + 1) % this.capacity;
    this.size++;
    return true;
  }

  public pop(): T | undefined {
    if (this.size === 0) {
      return undefined;
    }
    
    const item = this.buffer[this.tail];
    this.tail = (this.tail + 1) % this.capacity;
    this.size--;
    return item;
  }

  public peek(): T | undefined {
    if (this.size === 0) {
      return undefined;
    }
    return this.buffer[this.tail];
  }

  public getSize(): number {
    return this.size;
  }

  public getCapacity(): number {
    return this.capacity;
  }

  public clear(): void {
    this.head = 0;
    this.tail = 0;
    this.size = 0;
  }

  public toArray(): T[] {
    const result: T[] = [];
    let current = this.tail;
    let count = 0;
    
    while (count < this.size) {
      result.push(this.buffer[current]);
      current = (current + 1) % this.capacity;
      count++;
    }
    
    return result;
  }
}

// Throttled function for high-frequency updates
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout | null = null;
  let lastExecTime = 0;
  
  return (...args: Parameters<T>) => {
    const currentTime = Date.now();
    
    if (currentTime - lastExecTime > delay) {
      func(...args);
      lastExecTime = currentTime;
    } else {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      
      timeoutId = setTimeout(() => {
        func(...args);
        lastExecTime = Date.now();
      }, delay - (currentTime - lastExecTime));
    }
  };
}

// Debounced function for UI updates
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout | null = null;
  
  return (...args: Parameters<T>) => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    
    timeoutId = setTimeout(() => {
      func(...args);
    }, delay);
  };
} 