/**
 * Performance Testing Utilities
 *
 * Common utilities and helpers for performance testing across the suite.
 */

import { performance } from 'perf_hooks';

export interface PerformanceMeasurement {
  name: string;
  duration: number;
  startTime: number;
  endTime: number;
  metadata?: Record<string, any>;
}

export interface TimingResult {
  min: number;
  max: number;
  avg: number;
  p50: number;
  p95: number;
  p99: number;
  samples: number[];
}

export class PerformanceTimer {
  private startTime: number;
  private measurements: Map<string, PerformanceMeasurement[]> = new Map();

  start(): void {
    this.startTime = performance.now();
  }

  end(): number {
    return performance.now() - this.startTime;
  }

  measure<T>(name: string, fn: () => T, metadata?: Record<string, any>): T {
    const startTime = performance.now();
    const result = fn();
    const endTime = performance.now();

    this.recordMeasurement(name, endTime - startTime, startTime, endTime, metadata);
    return result;
  }

  async measureAsync<T>(name: string, fn: () => Promise<T>, metadata?: Record<string, any>): Promise<T> {
    const startTime = performance.now();
    const result = await fn();
    const endTime = performance.now();

    this.recordMeasurement(name, endTime - startTime, startTime, endTime, metadata);
    return result;
  }

  private recordMeasurement(name: string, duration: number, startTime: number, endTime: number, metadata?: Record<string, any>): void {
    if (!this.measurements.has(name)) {
      this.measurements.set(name, []);
    }

    this.measurements.get(name)!.push({
      name,
      duration,
      startTime,
      endTime,
      metadata
    });
  }

  getTimingResults(name: string): TimingResult | null {
    const measurements = this.measurements.get(name);
    if (!measurements || measurements.length === 0) {
      return null;
    }

    const samples = measurements.map(m => m.duration).sort((a, b) => a - b);
    return calculateTimingStats(samples);
  }

  getAllMeasurements(): Map<string, PerformanceMeasurement[]> {
    return new Map(this.measurements);
  }

  clear(): void {
    this.measurements.clear();
  }
}

export function calculateTimingStats(samples: number[]): TimingResult {
  if (samples.length === 0) {
    return { min: 0, max: 0, avg: 0, p50: 0, p95: 0, p99: 0, samples: [] };
  }

  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, val) => acc + val, 0);

  return {
    min: sorted[0],
    max: sorted[sorted.length - 1],
    avg: sum / sorted.length,
    p50: getPercentile(sorted, 50),
    p95: getPercentile(sorted, 95),
    p99: getPercentile(sorted, 99),
    samples: sorted
  };
}

export function getPercentile(sortedSamples: number[], percentile: number): number {
  if (sortedSamples.length === 0) return 0;

  const index = Math.ceil((percentile / 100) * sortedSamples.length) - 1;
  return sortedSamples[Math.max(0, Math.min(index, sortedSamples.length - 1))];
}

export function formatDuration(ms: number): string {
  if (ms < 1) return `${(ms * 1000).toFixed(2)}μs`;
  if (ms < 1000) return `${ms.toFixed(2)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  return `${(ms / 60000).toFixed(2)}min`;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function formatRate(count: number, durationMs: number, unit = 'ops'): string {
  const rate = (count / durationMs) * 1000; // per second
  if (rate < 1) return `${(rate * 1000).toFixed(2)} ${unit}/ms`;
  if (rate < 1000) return `${rate.toFixed(2)} ${unit}/s`;
  return `${(rate / 1000).toFixed(2)}K ${unit}/s`;
}

export class MemoryProfiler {
  private snapshots: NodeJS.MemoryUsage[] = [];
  private interval?: NodeJS.Timeout;

  start(intervalMs = 100): void {
    this.snapshots = [];
    this.interval = setInterval(() => {
      this.snapshots.push(process.memoryUsage());
    }, intervalMs);
  }

  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = undefined;
    }
  }

  getProfile() {
    if (this.snapshots.length === 0) {
      return null;
    }

    const initial = this.snapshots[0];
    const final = this.snapshots[this.snapshots.length - 1];

    const heapUsedSamples = this.snapshots.map(s => s.heapUsed);
    const rssSamples = this.snapshots.map(s => s.rss);

    return {
      initial,
      final,
      growth: {
        heapUsed: final.heapUsed - initial.heapUsed,
        heapTotal: final.heapTotal - initial.heapTotal,
        rss: final.rss - initial.rss,
        external: final.external - initial.external,
        arrayBuffers: final.arrayBuffers - initial.arrayBuffers
      },
      peak: {
        heapUsed: Math.max(...heapUsedSamples),
        rss: Math.max(...rssSamples)
      },
      samples: this.snapshots.length,
      duration: this.snapshots.length * 100 // Assuming 100ms intervals
    };
  }
}

export class CPUProfiler {
  private samples: number[] = [];
  private interval?: NodeJS.Timeout;
  private startUsage?: NodeJS.CpuUsage;

  start(intervalMs = 100): void {
    this.samples = [];
    this.startUsage = process.cpuUsage();

    this.interval = setInterval(() => {
      const currentUsage = process.cpuUsage(this.startUsage);
      // Simple CPU percentage calculation (not perfectly accurate)
      const cpuPercent = ((currentUsage.user + currentUsage.system) / (intervalMs * 1000)) * 100;
      this.samples.push(Math.min(100, cpuPercent));
    }, intervalMs);
  }

  stop(): void {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = undefined;
    }
  }

  getProfile() {
    if (this.samples.length === 0) {
      return null;
    }

    return calculateTimingStats(this.samples);
  }
}

export class NetworkSimulator {
  static simulateLatency(minMs: number, maxMs: number): Promise<void> {
    const latency = Math.random() * (maxMs - minMs) + minMs;
    return new Promise(resolve => setTimeout(resolve, latency));
  }

  static simulatePacketLoss(lossRate: number): boolean {
    return Math.random() < lossRate;
  }

  static simulateBandwidthLimit(dataSize: number, bandwidthBps: number): Promise<void> {
    const transmissionTimeMs = (dataSize / bandwidthBps) * 1000;
    return new Promise(resolve => setTimeout(resolve, transmissionTimeMs));
  }
}

export class LoadGenerator {
  private isRunning = false;
  private workers: Array<() => Promise<void>> = [];

  constructor(private concurrency = 10) {}

  async generateLoad<T>(
    workFunction: () => Promise<T>,
    options: {
      duration?: number;
      rate?: number;
      totalRequests?: number;
    } = {}
  ): Promise<{
    results: T[];
    errors: Error[];
    duration: number;
    actualRate: number;
  }> {
    const {
      duration = 10000,
      rate = 10,
      totalRequests
    } = options;

    const results: T[] = [];
    const errors: Error[] = [];
    const startTime = performance.now();

    this.isRunning = true;

    const requestInterval = 1000 / rate; // ms between requests
    let requestCount = 0;

    const generateRequest = async (): Promise<void> => {
      try {
        const result = await workFunction();
        results.push(result);
      } catch (error) {
        errors.push(error instanceof Error ? error : new Error(String(error)));
      }
    };

    // Generate load
    while (this.isRunning) {
      const shouldContinue = totalRequests ? requestCount < totalRequests :
                            (performance.now() - startTime) < duration;

      if (!shouldContinue) break;

      // Limit concurrency
      if (this.workers.length >= this.concurrency) {
        await Promise.race(this.workers);
        this.workers = this.workers.filter(worker => {
          // Remove completed workers (this is a simplified check)
          return true; // In real implementation, track completion
        });
      }

      const worker = generateRequest();
      this.workers.push(worker);
      requestCount++;

      // Rate limiting
      await new Promise(resolve => setTimeout(resolve, requestInterval));
    }

    // Wait for remaining workers
    await Promise.allSettled(this.workers);

    const endTime = performance.now();
    const actualDuration = endTime - startTime;
    const actualRate = (requestCount / actualDuration) * 1000;

    this.isRunning = false;
    this.workers = [];

    return {
      results,
      errors,
      duration: actualDuration,
      actualRate
    };
  }

  stop(): void {
    this.isRunning = false;
  }
}

export function createPerformanceThresholds(environment: 'development' | 'production' | 'ci') {
  const base = {
    development: {
      terminalRenderTime: 50,
      websocketLatency: 100,
      reactRenderTime: 20,
      memoryLeakThreshold: 100 * 1024 * 1024, // 100MB
      bundleSizeThreshold: 2 * 1024 * 1024, // 2MB
      loadTimeThreshold: 5000,
      errorRateThreshold: 0.05
    },
    production: {
      terminalRenderTime: 30,
      websocketLatency: 50,
      reactRenderTime: 16,
      memoryLeakThreshold: 50 * 1024 * 1024, // 50MB
      bundleSizeThreshold: 1 * 1024 * 1024, // 1MB
      loadTimeThreshold: 3000,
      errorRateThreshold: 0.01
    },
    ci: {
      terminalRenderTime: 100,
      websocketLatency: 200,
      reactRenderTime: 30,
      memoryLeakThreshold: 200 * 1024 * 1024, // 200MB
      bundleSizeThreshold: 3 * 1024 * 1024, // 3MB
      loadTimeThreshold: 10000,
      errorRateThreshold: 0.1
    }
  };

  return base[environment];
}

export class RegressionDetector {
  private baselines: Map<string, number> = new Map();

  loadBaselines(baselineData: Record<string, any>): void {
    for (const [key, value] of Object.entries(baselineData)) {
      if (typeof value === 'number') {
        this.baselines.set(key, value);
      } else if (typeof value === 'object' && value !== null) {
        // Handle nested objects
        for (const [subKey, subValue] of Object.entries(value)) {
          if (typeof subValue === 'number') {
            this.baselines.set(`${key}.${subKey}`, subValue);
          }
        }
      }
    }
  }

  checkRegression(
    metricName: string,
    currentValue: number,
    thresholdPercent = 15
  ): {
    isRegression: boolean;
    baseline?: number;
    change?: number;
    changePercent?: number;
  } {
    const baseline = this.baselines.get(metricName);

    if (baseline === undefined) {
      // No baseline, establish this as baseline
      this.baselines.set(metricName, currentValue);
      return { isRegression: false };
    }

    const change = currentValue - baseline;
    const changePercent = (change / baseline) * 100;
    const isRegression = Math.abs(changePercent) > thresholdPercent && change > 0;

    return {
      isRegression,
      baseline,
      change,
      changePercent
    };
  }

  getBaselines(): Map<string, number> {
    return new Map(this.baselines);
  }
}

// Singleton instances for global use
export const globalTimer = new PerformanceTimer();
export const globalMemoryProfiler = new MemoryProfiler();
export const globalCPUProfiler = new CPUProfiler();
export const globalRegressionDetector = new RegressionDetector();