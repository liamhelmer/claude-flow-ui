/**
 * Performance Testing Harness for TDD
 * Comprehensive framework for performance testing and benchmarking
 */

import { performance } from 'perf_hooks';
import { jest } from '@jest/globals';

/**
 * Performance Metrics Interface
 */
export interface PerformanceMetrics {
  name: string;
  duration: number;
  memoryUsage: {
    heapUsed: number;
    heapTotal: number;
    external: number;
    arrayBuffers: number;
  };
  iterations: number;
  averageDuration: number;
  minDuration: number;
  maxDuration: number;
  standardDeviation: number;
  operationsPerSecond: number;
}

/**
 * Benchmark Configuration
 */
export interface BenchmarkConfig {
  name: string;
  iterations?: number;
  warmupIterations?: number;
  timeout?: number;
  memoryTracking?: boolean;
  async?: boolean;
}

/**
 * Performance Test Result
 */
export interface PerformanceTestResult {
  passed: boolean;
  metrics: PerformanceMetrics;
  threshold?: number;
  actualValue: number;
  message?: string;
}

/**
 * Benchmark Runner
 */
export class BenchmarkRunner {
  private results: Map<string, PerformanceMetrics> = new Map();

  /**
   * Run synchronous benchmark
   */
  async runSync<T>(
    fn: () => T,
    config: BenchmarkConfig
  ): Promise<PerformanceMetrics> {
    const {
      name,
      iterations = 100,
      warmupIterations = 10,
      memoryTracking = true,
    } = config;

    // Warmup
    for (let i = 0; i < warmupIterations; i++) {
      fn();
    }

    // Collect garbage before measurement
    if (global.gc) {
      global.gc();
    }

    const durations: number[] = [];
    let initialMemory: NodeJS.MemoryUsage | null = null;

    if (memoryTracking) {
      initialMemory = process.memoryUsage();
    }

    // Run benchmarks
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      fn();
      const end = performance.now();
      durations.push(end - start);
    }

    let finalMemory: NodeJS.MemoryUsage | null = null;
    if (memoryTracking) {
      finalMemory = process.memoryUsage();
    }

    const metrics = this.calculateMetrics(
      name,
      durations,
      initialMemory,
      finalMemory
    );

    this.results.set(name, metrics);
    return metrics;
  }

  /**
   * Run asynchronous benchmark
   */
  async runAsync<T>(
    fn: () => Promise<T>,
    config: BenchmarkConfig
  ): Promise<PerformanceMetrics> {
    const {
      name,
      iterations = 100,
      warmupIterations = 10,
      memoryTracking = true,
    } = config;

    // Warmup
    for (let i = 0; i < warmupIterations; i++) {
      await fn();
    }

    // Collect garbage before measurement
    if (global.gc) {
      global.gc();
    }

    const durations: number[] = [];
    let initialMemory: NodeJS.MemoryUsage | null = null;

    if (memoryTracking) {
      initialMemory = process.memoryUsage();
    }

    // Run benchmarks
    for (let i = 0; i < iterations; i++) {
      const start = performance.now();
      await fn();
      const end = performance.now();
      durations.push(end - start);
    }

    let finalMemory: NodeJS.MemoryUsage | null = null;
    if (memoryTracking) {
      finalMemory = process.memoryUsage();
    }

    const metrics = this.calculateMetrics(
      name,
      durations,
      initialMemory,
      finalMemory
    );

    this.results.set(name, metrics);
    return metrics;
  }

  /**
   * Calculate performance metrics
   */
  private calculateMetrics(
    name: string,
    durations: number[],
    initialMemory: NodeJS.MemoryUsage | null,
    finalMemory: NodeJS.MemoryUsage | null
  ): PerformanceMetrics {
    const totalDuration = durations.reduce((a, b) => a + b, 0);
    const averageDuration = totalDuration / durations.length;
    const minDuration = Math.min(...durations);
    const maxDuration = Math.max(...durations);

    // Calculate standard deviation
    const variance = durations.reduce(
      (acc, duration) => acc + Math.pow(duration - averageDuration, 2),
      0
    ) / durations.length;
    const standardDeviation = Math.sqrt(variance);

    const operationsPerSecond = 1000 / averageDuration;

    const memoryUsage = {
      heapUsed: finalMemory ? finalMemory.heapUsed - (initialMemory?.heapUsed || 0) : 0,
      heapTotal: finalMemory ? finalMemory.heapTotal - (initialMemory?.heapTotal || 0) : 0,
      external: finalMemory ? finalMemory.external - (initialMemory?.external || 0) : 0,
      arrayBuffers: finalMemory ? finalMemory.arrayBuffers - (initialMemory?.arrayBuffers || 0) : 0,
    };

    return {
      name,
      duration: totalDuration,
      memoryUsage,
      iterations: durations.length,
      averageDuration,
      minDuration,
      maxDuration,
      standardDeviation,
      operationsPerSecond,
    };
  }

  /**
   * Get benchmark results
   */
  getResults(): Map<string, PerformanceMetrics> {
    return this.results;
  }

  /**
   * Get result by name
   */
  getResult(name: string): PerformanceMetrics | undefined {
    return this.results.get(name);
  }

  /**
   * Clear all results
   */
  clearResults(): void {
    this.results.clear();
  }

  /**
   * Compare two benchmark results
   */
  compare(nameA: string, nameB: string): {
    faster: string;
    slower: string;
    speedup: number;
    difference: number;
  } {
    const resultA = this.results.get(nameA);
    const resultB = this.results.get(nameB);

    if (!resultA || !resultB) {
      throw new Error('Cannot compare: one or both benchmarks not found');
    }

    const speedup = resultB.averageDuration / resultA.averageDuration;
    const difference = resultB.averageDuration - resultA.averageDuration;

    return {
      faster: speedup > 1 ? nameA : nameB,
      slower: speedup > 1 ? nameB : nameA,
      speedup: Math.max(speedup, 1 / speedup),
      difference: Math.abs(difference),
    };
  }
}

/**
 * Performance Assertion Builder
 */
export class PerformanceAssertions {
  private metrics: PerformanceMetrics;

  constructor(metrics: PerformanceMetrics) {
    this.metrics = metrics;
  }

  /**
   * Assert duration is less than threshold
   */
  toBeFasterThan(milliseconds: number): PerformanceTestResult {
    const passed = this.metrics.averageDuration < milliseconds;
    return {
      passed,
      metrics: this.metrics,
      threshold: milliseconds,
      actualValue: this.metrics.averageDuration,
      message: passed
        ? `✓ ${this.metrics.name} completed in ${this.metrics.averageDuration.toFixed(2)}ms (< ${milliseconds}ms)`
        : `✗ ${this.metrics.name} took ${this.metrics.averageDuration.toFixed(2)}ms (> ${milliseconds}ms)`,
    };
  }

  /**
   * Assert operations per second is greater than threshold
   */
  toHandleAtLeast(operationsPerSecond: number): PerformanceTestResult {
    const passed = this.metrics.operationsPerSecond >= operationsPerSecond;
    return {
      passed,
      metrics: this.metrics,
      threshold: operationsPerSecond,
      actualValue: this.metrics.operationsPerSecond,
      message: passed
        ? `✓ ${this.metrics.name} handles ${this.metrics.operationsPerSecond.toFixed(2)} ops/sec (>= ${operationsPerSecond})`
        : `✗ ${this.metrics.name} handles ${this.metrics.operationsPerSecond.toFixed(2)} ops/sec (< ${operationsPerSecond})`,
    };
  }

  /**
   * Assert memory usage is less than threshold
   */
  toUseMemoryLessThan(bytes: number): PerformanceTestResult {
    const passed = this.metrics.memoryUsage.heapUsed < bytes;
    return {
      passed,
      metrics: this.metrics,
      threshold: bytes,
      actualValue: this.metrics.memoryUsage.heapUsed,
      message: passed
        ? `✓ ${this.metrics.name} used ${this.formatBytes(this.metrics.memoryUsage.heapUsed)} (< ${this.formatBytes(bytes)})`
        : `✗ ${this.metrics.name} used ${this.formatBytes(this.metrics.memoryUsage.heapUsed)} (> ${this.formatBytes(bytes)})`,
    };
  }

  /**
   * Assert standard deviation is less than percentage of average
   */
  toBeConsistentWithin(percentageThreshold: number): PerformanceTestResult {
    const consistencyRatio = (this.metrics.standardDeviation / this.metrics.averageDuration) * 100;
    const passed = consistencyRatio <= percentageThreshold;
    return {
      passed,
      metrics: this.metrics,
      threshold: percentageThreshold,
      actualValue: consistencyRatio,
      message: passed
        ? `✓ ${this.metrics.name} is consistent (σ: ${consistencyRatio.toFixed(2)}% <= ${percentageThreshold}%)`
        : `✗ ${this.metrics.name} is inconsistent (σ: ${consistencyRatio.toFixed(2)}% > ${percentageThreshold}%)`,
    };
  }

  /**
   * Assert performance is better than baseline
   */
  toBeFasterThanBaseline(baseline: PerformanceMetrics, improvementThreshold: number = 1.1): PerformanceTestResult {
    const speedup = baseline.averageDuration / this.metrics.averageDuration;
    const passed = speedup >= improvementThreshold;
    return {
      passed,
      metrics: this.metrics,
      threshold: improvementThreshold,
      actualValue: speedup,
      message: passed
        ? `✓ ${this.metrics.name} is ${speedup.toFixed(2)}x faster than baseline (>= ${improvementThreshold}x)`
        : `✗ ${this.metrics.name} is ${speedup.toFixed(2)}x faster than baseline (< ${improvementThreshold}x)`,
    };
  }

  /**
   * Format bytes to human readable format
   */
  private formatBytes(bytes: number): string {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    if (bytes === 0) return '0 Bytes';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return parseFloat((bytes / Math.pow(1024, i)).toFixed(2)) + ' ' + sizes[i];
  }
}

/**
 * Load Testing Framework
 */
export class LoadTester {
  private activeRequests = 0;
  private results: Array<{
    duration: number;
    success: boolean;
    error?: string;
  }> = [];

  /**
   * Run load test
   */
  async runLoadTest<T>(
    fn: () => Promise<T>,
    config: {
      concurrency: number;
      duration: number; // in milliseconds
      rampUp?: number; // in milliseconds
    }
  ): Promise<{
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    averageResponseTime: number;
    requestsPerSecond: number;
    errors: string[];
  }> {
    const { concurrency, duration, rampUp = 0 } = config;
    const startTime = Date.now();
    const endTime = startTime + duration;

    // Ramp up workers
    const workers: Promise<void>[] = [];
    const rampUpInterval = rampUp / concurrency;

    for (let i = 0; i < concurrency; i++) {
      const delay = i * rampUpInterval;
      workers.push(this.runWorker(fn, delay, endTime));
    }

    await Promise.all(workers);

    // Calculate results
    const totalRequests = this.results.length;
    const successfulRequests = this.results.filter(r => r.success).length;
    const failedRequests = totalRequests - successfulRequests;
    const averageResponseTime = this.results.reduce((sum, r) => sum + r.duration, 0) / totalRequests;
    const actualDuration = (Date.now() - startTime) / 1000;
    const requestsPerSecond = totalRequests / actualDuration;
    const errors = this.results
      .filter(r => !r.success && r.error)
      .map(r => r.error!)
      .filter((error, index, array) => array.indexOf(error) === index); // unique errors

    return {
      totalRequests,
      successfulRequests,
      failedRequests,
      averageResponseTime,
      requestsPerSecond,
      errors,
    };
  }

  /**
   * Run individual worker
   */
  private async runWorker<T>(
    fn: () => Promise<T>,
    delay: number,
    endTime: number
  ): Promise<void> {
    if (delay > 0) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }

    while (Date.now() < endTime) {
      this.activeRequests++;
      const start = performance.now();

      try {
        await fn();
        this.results.push({
          duration: performance.now() - start,
          success: true,
        });
      } catch (error) {
        this.results.push({
          duration: performance.now() - start,
          success: false,
          error: error instanceof Error ? error.message : String(error),
        });
      } finally {
        this.activeRequests--;
      }
    }
  }

  /**
   * Clear results
   */
  clearResults(): void {
    this.results = [];
  }
}

/**
 * Memory Profiler
 */
export class MemoryProfiler {
  private snapshots: Array<{
    name: string;
    timestamp: number;
    memory: NodeJS.MemoryUsage;
  }> = [];

  /**
   * Take memory snapshot
   */
  snapshot(name: string): void {
    if (global.gc) {
      global.gc();
    }

    this.snapshots.push({
      name,
      timestamp: Date.now(),
      memory: process.memoryUsage(),
    });
  }

  /**
   * Get memory diff between two snapshots
   */
  diff(fromSnapshot: string, toSnapshot: string): {
    heapUsed: number;
    heapTotal: number;
    external: number;
    arrayBuffers: number;
    duration: number;
  } {
    const from = this.snapshots.find(s => s.name === fromSnapshot);
    const to = this.snapshots.find(s => s.name === toSnapshot);

    if (!from || !to) {
      throw new Error('Snapshot not found');
    }

    return {
      heapUsed: to.memory.heapUsed - from.memory.heapUsed,
      heapTotal: to.memory.heapTotal - from.memory.heapTotal,
      external: to.memory.external - from.memory.external,
      arrayBuffers: to.memory.arrayBuffers - from.memory.arrayBuffers,
      duration: to.timestamp - from.timestamp,
    };
  }

  /**
   * Clear all snapshots
   */
  clearSnapshots(): void {
    this.snapshots = [];
  }

  /**
   * Get all snapshots
   */
  getSnapshots(): Array<{
    name: string;
    timestamp: number;
    memory: NodeJS.MemoryUsage;
  }> {
    return [...this.snapshots];
  }
}

/**
 * Performance Test Suite Builder
 */
export class PerformanceTestSuite {
  private runner = new BenchmarkRunner();
  private memoryProfiler = new MemoryProfiler();
  private loadTester = new LoadTester();

  /**
   * Run benchmark
   */
  async benchmark<T>(
    fn: () => T,
    config: BenchmarkConfig
  ): Promise<PerformanceAssertions> {
    const metrics = await this.runner.runSync(fn, config);
    return new PerformanceAssertions(metrics);
  }

  /**
   * Run async benchmark
   */
  async benchmarkAsync<T>(
    fn: () => Promise<T>,
    config: BenchmarkConfig
  ): Promise<PerformanceAssertions> {
    const metrics = await this.runner.runAsync(fn, config);
    return new PerformanceAssertions(metrics);
  }

  /**
   * Run load test
   */
  async loadTest<T>(
    fn: () => Promise<T>,
    config: {
      concurrency: number;
      duration: number;
      rampUp?: number;
    }
  ): Promise<ReturnType<LoadTester['runLoadTest']>> {
    return this.loadTester.runLoadTest(fn, config);
  }

  /**
   * Take memory snapshot
   */
  memorySnapshot(name: string): void {
    this.memoryProfiler.snapshot(name);
  }

  /**
   * Get memory diff
   */
  memoryDiff(from: string, to: string): ReturnType<MemoryProfiler['diff']> {
    return this.memoryProfiler.diff(from, to);
  }

  /**
   * Get benchmark results
   */
  getResults(): Map<string, PerformanceMetrics> {
    return this.runner.getResults();
  }

  /**
   * Compare benchmarks
   */
  compare(nameA: string, nameB: string): ReturnType<BenchmarkRunner['compare']> {
    return this.runner.compare(nameA, nameB);
  }

  /**
   * Clear all data
   */
  clear(): void {
    this.runner.clearResults();
    this.memoryProfiler.clearSnapshots();
    this.loadTester.clearResults();
  }
}

/**
 * Factory function to create performance test suite
 */
export const createPerformanceTestSuite = (): PerformanceTestSuite => {
  return new PerformanceTestSuite();
};

/**
 * Utility functions for performance testing
 */
export const performanceTestUtils = {
  /**
   * Measure function execution time
   */
  measure: async <T>(fn: () => T | Promise<T>): Promise<{ result: T; duration: number }> => {
    const start = performance.now();
    const result = await fn();
    const duration = performance.now() - start;
    return { result, duration };
  },

  /**
   * Create CPU intensive task for testing
   */
  createCpuIntensiveTask: (iterations: number = 1000000) => {
    return () => {
      let sum = 0;
      for (let i = 0; i < iterations; i++) {
        sum += Math.random() * Math.sin(i) * Math.cos(i);
      }
      return sum;
    };
  },

  /**
   * Create memory intensive task for testing
   */
  createMemoryIntensiveTask: (arraySize: number = 1000000) => {
    return () => {
      const array = new Array(arraySize).fill(0).map((_, i) => ({
        id: i,
        data: Math.random().toString(36),
        nested: { value: Math.random() },
      }));
      return array.length;
    };
  },

  /**
   * Format performance results for display
   */
  formatResults: (metrics: PerformanceMetrics): string => {
    return `
Performance Results for ${metrics.name}:
- Iterations: ${metrics.iterations}
- Average Duration: ${metrics.averageDuration.toFixed(2)}ms
- Min/Max: ${metrics.minDuration.toFixed(2)}ms / ${metrics.maxDuration.toFixed(2)}ms
- Standard Deviation: ${metrics.standardDeviation.toFixed(2)}ms
- Operations/Second: ${metrics.operationsPerSecond.toFixed(2)}
- Memory Usage: ${(metrics.memoryUsage.heapUsed / 1024 / 1024).toFixed(2)}MB
    `.trim();
  },
};

// Export everything
export default {
  createPerformanceTestSuite,
  PerformanceTestSuite,
  BenchmarkRunner,
  PerformanceAssertions,
  LoadTester,
  MemoryProfiler,
  performanceTestUtils,
};