/**
 * Performance Testing Framework - Mock Implementation
 * Addresses PerformanceObserver issues in jsdom environment
 */

export interface PerformanceMetrics {
  renderTime: number;
  memoryUsage: number;
  componentCount: number;
  rerenderCount: number;
}

export interface MockPerformanceEntry {
  name: string;
  entryType: string;
  startTime: number;
  duration: number;
}

// Mock PerformanceObserver for jsdom environment
export class MockPerformanceObserver {
  private callback: (list: { getEntries: () => MockPerformanceEntry[] }) => void;
  private entries: MockPerformanceEntry[] = [];
  
  constructor(callback: (list: { getEntries: () => MockPerformanceEntry[] }) => void) {
    this.callback = callback;
  }
  
  observe(options: { entryTypes: string[] }): void {
    // Simulate observation
  }
  
  disconnect(): void {
    this.entries = [];
  }
  
  takeRecords(): MockPerformanceEntry[] {
    return this.entries.splice(0);
  }
  
  // Simulate performance entries
  static addEntry(entry: MockPerformanceEntry): void {
    // This would be called by our test utilities
  }
}

// Enhanced performance measurement utilities
export class PerformanceTestUtils {
  private static startTimes = new Map<string, number>();
  private static memoryBaseline = 0;
  
  static startMeasurement(label: string): void {
    this.startTimes.set(label, performance.now());
  }
  
  static endMeasurement(label: string): number {
    const startTime = this.startTimes.get(label);
    if (!startTime) {
      throw new Error(`No start time found for measurement: ${label}`);
    }
    
    const duration = performance.now() - startTime;
    this.startTimes.delete(label);
    return duration;
  }
  
  static measureMemoryUsage(): number {
    // Use performance.memory if available, otherwise simulate
    if (typeof performance !== 'undefined' && 'memory' in performance) {
      return (performance.memory as any).usedJSHeapSize;
    }
    
    // Simulate memory usage for testing
    return Math.floor(Math.random() * 10 * 1024 * 1024); // Random 0-10MB
  }
  
  static setMemoryBaseline(): void {
    this.memoryBaseline = this.measureMemoryUsage();
  }
  
  static getMemoryDelta(): number {
    return this.measureMemoryUsage() - this.memoryBaseline;
  }
  
  static async measureRenderPerformance<T>(
    renderFunction: () => T,
    options: { 
      iterations?: number;
      warmup?: number;
      timeout?: number;
    } = {}
  ): Promise<PerformanceMetrics> {
    const { iterations = 1, warmup = 0, timeout = 5000 } = options;
    
    // Warmup runs
    for (let i = 0; i < warmup; i++) {
      renderFunction();
    }
    
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
    
    this.setMemoryBaseline();
    const times: number[] = [];
    
    for (let i = 0; i < iterations; i++) {
      const startTime = performance.now();
      
      // Wrap in timeout
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`Render timeout after ${timeout}ms`)), timeout);
      });
      
      try {
        await Promise.race([
          Promise.resolve(renderFunction()),
          timeoutPromise
        ]);
        
        const endTime = performance.now();
        times.push(endTime - startTime);
      } catch (error) {
        throw new Error(`Render failed on iteration ${i + 1}: ${error instanceof Error ? error.message : 'Unknown error'}`);
      }
    }
    
    const avgRenderTime = times.reduce((a, b) => a + b, 0) / times.length;
    const memoryDelta = this.getMemoryDelta();
    
    return {
      renderTime: avgRenderTime,
      memoryUsage: memoryDelta,
      componentCount: 1, // This would be calculated from React internals
      rerenderCount: 0   // This would be tracked during test execution
    };
  }
  
  static async measureAsyncOperation<T>(
    operation: () => Promise<T>,
    expectedDuration?: number
  ): Promise<{ result: T; duration: number; withinExpectation: boolean }> {
    const startTime = performance.now();
    const result = await operation();
    const duration = performance.now() - startTime;
    
    const withinExpectation = expectedDuration ? duration <= expectedDuration : true;
    
    return {
      result,
      duration,
      withinExpectation
    };
  }
  
  static createPerformanceBenchmark(name: string, threshold: number) {
    return async (testFunction: () => Promise<void> | void) => {
      const startTime = performance.now();
      await testFunction();
      const duration = performance.now() - startTime;
      
      if (duration > threshold) {
        console.warn(`⚠️  Performance benchmark '${name}' exceeded threshold: ${duration.toFixed(2)}ms > ${threshold}ms`);
      }
      
      return {
        name,
        duration,
        threshold,
        passed: duration <= threshold
      };
    };
  }
  
  static reset(): void {
    this.startTimes.clear();
    this.memoryBaseline = 0;
  }
}

// Memory leak detection utility
export class MemoryLeakDetector {
  private static checkpoints = new Map<string, number>();
  
  static checkpoint(name: string): void {
    this.checkpoints.set(name, PerformanceTestUtils.measureMemoryUsage());
  }
  
  static checkForLeak(name: string, tolerance = 1024 * 1024): { hasLeak: boolean; delta: number } {
    const baseline = this.checkpoints.get(name);
    if (!baseline) {
      throw new Error(`No checkpoint found: ${name}`);
    }
    
    const current = PerformanceTestUtils.measureMemoryUsage();
    const delta = current - baseline;
    
    return {
      hasLeak: delta > tolerance,
      delta
    };
  }
}

// Test utilities for component performance
export const performanceTestHelpers = {
  measureComponentRender: async (component: () => JSX.Element, props?: any) => {
    return PerformanceTestUtils.measureRenderPerformance(() => {
      // This would integrate with React testing utilities
      return component();
    });
  },
  
  checkMemoryLeak: (componentTest: () => void, tolerance = 1024 * 1024) => {
    MemoryLeakDetector.checkpoint('before');
    componentTest();
    
    // Force cleanup
    if (global.gc) {
      global.gc();
    }
    
    const result = MemoryLeakDetector.checkForLeak('before', tolerance);
    return result;
  },
  
  benchmarkComponentMount: PerformanceTestUtils.createPerformanceBenchmark('component-mount', 50),
  benchmarkComponentUpdate: PerformanceTestUtils.createPerformanceBenchmark('component-update', 20),
  benchmarkComponentUnmount: PerformanceTestUtils.createPerformanceBenchmark('component-unmount', 10),
};

// Global setup for performance testing
export const setupPerformanceTesting = (): void => {
  // Mock PerformanceObserver globally
  global.PerformanceObserver = MockPerformanceObserver as any;
  
  // Mock performance.mark and performance.measure
  if (typeof global.performance === 'undefined') {
    global.performance = {} as Performance;
  }
  
  global.performance.mark = jest.fn();
  global.performance.measure = jest.fn();
  global.performance.getEntriesByType = jest.fn(() => []);
  global.performance.getEntriesByName = jest.fn(() => []);
  
  // Mock performance.memory for memory testing
  Object.defineProperty(global.performance, 'memory', {
    value: {
      usedJSHeapSize: 0,
      totalJSHeapSize: 100 * 1024 * 1024, // 100MB
      jsHeapSizeLimit: 1000 * 1024 * 1024, // 1GB
    },
    configurable: true
  });
  
  // Setup cleanup
  afterEach(() => {
    PerformanceTestUtils.reset();
  });
};

export default {
  MockPerformanceObserver,
  PerformanceTestUtils,
  MemoryLeakDetector,
  performanceTestHelpers,
  setupPerformanceTesting
};