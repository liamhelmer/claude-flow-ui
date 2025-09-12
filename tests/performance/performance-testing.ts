/**
 * Performance Testing Framework
 * Comprehensive performance testing utilities for React components
 */
import { render, act } from '@testing-library/react';
import type { ReactElement } from 'react';

export interface PerformanceMetrics {
  renderTime: number;
  reRenderTime?: number;
  memoryUsage: number;
  memoryLeaks?: number;
  interactionTime?: number;
  paintTime?: number;
  layoutTime?: number;
}

export interface PerformanceThresholds {
  maxRenderTime: number; // milliseconds
  maxReRenderTime: number; // milliseconds
  maxMemoryUsage: number; // bytes
  maxMemoryLeaks: number; // bytes
  maxInteractionTime: number; // milliseconds
}

export interface LoadTestOptions {
  iterations: number;
  concurrency?: number;
  dataSize?: number;
  timeout?: number;
}

// Default performance thresholds
export const DEFAULT_THRESHOLDS: PerformanceThresholds = {
  maxRenderTime: 100, // 100ms
  maxReRenderTime: 50, // 50ms
  maxMemoryUsage: 1024 * 1024, // 1MB
  maxMemoryLeaks: 1024 * 100, // 100KB
  maxInteractionTime: 16 // 16ms (60fps)
};

/**
 * Measure component rendering performance
 */
export const measureRenderPerformance = async (
  component: ReactElement,
  iterations: number = 10
): Promise<PerformanceMetrics> => {
  const renderTimes: number[] = [];
  const memoryUsages: number[] = [];
  
  for (let i = 0; i < iterations; i++) {
    // Force garbage collection before measurement if available
    if ((global as any).gc) {
      (global as any).gc();
    }
    
    const startMemory = (performance as any).memory?.usedJSHeapSize || 0;
    const startTime = performance.now();
    
    const { unmount } = render(component);
    
    const endTime = performance.now();
    const endMemory = (performance as any).memory?.usedJSHeapSize || 0;
    
    renderTimes.push(endTime - startTime);
    memoryUsages.push(endMemory - startMemory);
    
    unmount();
  }
  
  return {
    renderTime: renderTimes.reduce((a, b) => a + b, 0) / renderTimes.length,
    memoryUsage: memoryUsages.reduce((a, b) => a + b, 0) / memoryUsages.length
  };
};

/**
 * Measure re-rendering performance
 */
export const measureReRenderPerformance = async (
  initialComponent: ReactElement,
  updatedComponent: ReactElement,
  iterations: number = 10
): Promise<PerformanceMetrics> => {
  const reRenderTimes: number[] = [];
  const memoryUsages: number[] = [];
  
  for (let i = 0; i < iterations; i++) {
    if ((global as any).gc) {
      (global as any).gc();
    }
    
    const { rerender, unmount } = render(initialComponent);
    
    const startMemory = (performance as any).memory?.usedJSHeapSize || 0;
    const startTime = performance.now();
    
    rerender(updatedComponent);
    
    const endTime = performance.now();
    const endMemory = (performance as any).memory?.usedJSHeapSize || 0;
    
    reRenderTimes.push(endTime - startTime);
    memoryUsages.push(endMemory - startMemory);
    
    unmount();
  }
  
  return {
    renderTime: 0,
    reRenderTime: reRenderTimes.reduce((a, b) => a + b, 0) / reRenderTimes.length,
    memoryUsage: memoryUsages.reduce((a, b) => a + b, 0) / memoryUsages.length
  };
};

/**
 * Test for memory leaks during mount/unmount cycles
 */
export const testMemoryLeaks = async (
  component: ReactElement,
  cycles: number = 100
): Promise<number> => {
  if ((global as any).gc) {
    (global as any).gc();
  }
  
  const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;
  
  for (let i = 0; i < cycles; i++) {
    const { unmount } = render(component);
    unmount();
    
    // Periodic garbage collection
    if (i % 10 === 0 && (global as any).gc) {
      (global as any).gc();
    }
  }
  
  // Final garbage collection
  if ((global as any).gc) {
    (global as any).gc();
  }
  
  const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
  return finalMemory - initialMemory;
};

/**
 * Measure interaction performance (e.g., click response time)
 */
export const measureInteractionPerformance = async (
  component: ReactElement,
  interaction: (container: HTMLElement) => Promise<void>,
  iterations: number = 10
): Promise<number> => {
  const { container } = render(component);
  const interactionTimes: number[] = [];
  
  for (let i = 0; i < iterations; i++) {
    const startTime = performance.now();
    
    await act(async () => {
      await interaction(container);
    });
    
    const endTime = performance.now();
    interactionTimes.push(endTime - startTime);
  }
  
  return interactionTimes.reduce((a, b) => a + b, 0) / interactionTimes.length;
};

/**
 * Load testing for components with large datasets
 */
export const loadTestComponent = async (
  ComponentFactory: (props: any) => ReactElement,
  generateProps: (size: number) => any,
  options: LoadTestOptions
): Promise<PerformanceMetrics[]> => {
  const { iterations, concurrency = 1, dataSize = 1000 } = options;
  const results: PerformanceMetrics[] = [];
  
  for (let i = 0; i < iterations; i++) {
    const props = generateProps(dataSize * (i + 1));
    const component = ComponentFactory(props);
    
    const metrics = await measureRenderPerformance(component);
    results.push(metrics);
    
    // Check if performance degrades significantly
    if (results.length > 1) {
      const previousRenderTime = results[results.length - 2].renderTime;
      const currentRenderTime = metrics.renderTime;
      
      if (currentRenderTime > previousRenderTime * 2) {
        console.warn(`Performance degradation detected at iteration ${i + 1}`);
        console.warn(`Previous: ${previousRenderTime}ms, Current: ${currentRenderTime}ms`);
      }
    }
  }
  
  return results;
};

/**
 * Stress test component with rapid updates
 */
export const stressTestComponent = async (
  component: ReactElement,
  updateFunction: (container: HTMLElement) => Promise<void>,
  duration: number = 5000 // 5 seconds
): Promise<{
  updatesPerformed: number;
  averageUpdateTime: number;
  memoryGrowth: number;
}> => {
  const { container } = render(component);
  const startTime = performance.now();
  const startMemory = (performance as any).memory?.usedJSHeapSize || 0;
  
  let updatesPerformed = 0;
  const updateTimes: number[] = [];
  
  while (performance.now() - startTime < duration) {
    const updateStartTime = performance.now();
    
    await act(async () => {
      await updateFunction(container);
    });
    
    const updateEndTime = performance.now();
    updateTimes.push(updateEndTime - updateStartTime);
    updatesPerformed++;
  }
  
  const endMemory = (performance as any).memory?.usedJSHeapSize || 0;
  
  return {
    updatesPerformed,
    averageUpdateTime: updateTimes.reduce((a, b) => a + b, 0) / updateTimes.length,
    memoryGrowth: endMemory - startMemory
  };
};

/**
 * Benchmark component against performance thresholds
 */
export const benchmarkComponent = async (
  component: ReactElement,
  thresholds: Partial<PerformanceThresholds> = {}
): Promise<{
  passed: boolean;
  metrics: PerformanceMetrics;
  failures: string[];
}> => {
  const finalThresholds = { ...DEFAULT_THRESHOLDS, ...thresholds };
  const failures: string[] = [];
  
  // Measure render performance
  const renderMetrics = await measureRenderPerformance(component);
  
  // Measure memory leaks
  const memoryLeaks = await testMemoryLeaks(component);
  
  const metrics: PerformanceMetrics = {
    ...renderMetrics,
    memoryLeaks
  };
  
  // Check against thresholds
  if (metrics.renderTime > finalThresholds.maxRenderTime) {
    failures.push(`Render time ${metrics.renderTime}ms exceeds threshold ${finalThresholds.maxRenderTime}ms`);
  }
  
  if (metrics.reRenderTime && metrics.reRenderTime > finalThresholds.maxReRenderTime) {
    failures.push(`Re-render time ${metrics.reRenderTime}ms exceeds threshold ${finalThresholds.maxReRenderTime}ms`);
  }
  
  if (metrics.memoryUsage > finalThresholds.maxMemoryUsage) {
    failures.push(`Memory usage ${metrics.memoryUsage} bytes exceeds threshold ${finalThresholds.maxMemoryUsage} bytes`);
  }
  
  if (metrics.memoryLeaks && metrics.memoryLeaks > finalThresholds.maxMemoryLeaks) {
    failures.push(`Memory leaks ${metrics.memoryLeaks} bytes exceeds threshold ${finalThresholds.maxMemoryLeaks} bytes`);
  }
  
  return {
    passed: failures.length === 0,
    metrics,
    failures
  };
};

/**
 * Performance regression testing
 */
export const testPerformanceRegression = async (
  baselineComponent: ReactElement,
  updatedComponent: ReactElement,
  regressionThreshold: number = 1.2 // 20% regression threshold
): Promise<{
  hasRegression: boolean;
  baselineMetrics: PerformanceMetrics;
  updatedMetrics: PerformanceMetrics;
  regressionFactor: number;
}> => {
  const baselineMetrics = await measureRenderPerformance(baselineComponent);
  const updatedMetrics = await measureRenderPerformance(updatedComponent);
  
  const regressionFactor = updatedMetrics.renderTime / baselineMetrics.renderTime;
  const hasRegression = regressionFactor > regressionThreshold;
  
  return {
    hasRegression,
    baselineMetrics,
    updatedMetrics,
    regressionFactor
  };
};

/**
 * Generate performance report
 */
export const generatePerformanceReport = (
  componentName: string,
  metrics: PerformanceMetrics,
  thresholds: PerformanceThresholds
): string => {
  const report = [
    `Performance Report for ${componentName}`,
    '='.repeat(50),
    '',
    `Render Time: ${metrics.renderTime.toFixed(2)}ms (threshold: ${thresholds.maxRenderTime}ms)`,
    metrics.reRenderTime ? `Re-render Time: ${metrics.reRenderTime.toFixed(2)}ms (threshold: ${thresholds.maxReRenderTime}ms)` : '',
    `Memory Usage: ${(metrics.memoryUsage / 1024).toFixed(2)}KB (threshold: ${(thresholds.maxMemoryUsage / 1024).toFixed(2)}KB)`,
    metrics.memoryLeaks ? `Memory Leaks: ${(metrics.memoryLeaks / 1024).toFixed(2)}KB (threshold: ${(thresholds.maxMemoryLeaks / 1024).toFixed(2)}KB)` : '',
    metrics.interactionTime ? `Interaction Time: ${metrics.interactionTime.toFixed(2)}ms (threshold: ${thresholds.maxInteractionTime}ms)` : '',
    '',
    'Status: ' + (
      metrics.renderTime <= thresholds.maxRenderTime &&
      (!metrics.reRenderTime || metrics.reRenderTime <= thresholds.maxReRenderTime) &&
      metrics.memoryUsage <= thresholds.maxMemoryUsage &&
      (!metrics.memoryLeaks || metrics.memoryLeaks <= thresholds.maxMemoryLeaks) &&
      (!metrics.interactionTime || metrics.interactionTime <= thresholds.maxInteractionTime)
        ? '✅ PASSED'
        : '❌ FAILED'
    )
  ].filter(Boolean).join('\n');
  
  return report;
};

/**
 * Create performance test suite for a component
 */
export const createPerformanceTestSuite = (
  componentName: string,
  component: ReactElement,
  options: {
    thresholds?: Partial<PerformanceThresholds>;
    skipMemoryLeakTest?: boolean;
    skipLoadTest?: boolean;
    loadTestFactory?: (size: number) => ReactElement;
  } = {}
) => {
  const { thresholds = {}, skipMemoryLeakTest, skipLoadTest, loadTestFactory } = options;
  
  return describe(`${componentName} Performance`, () => {
    it('should render within performance thresholds', async () => {
      const result = await benchmarkComponent(component, thresholds);
      
      if (!result.passed) {
        console.error('Performance failures:', result.failures.join('\n'));
        console.log(generatePerformanceReport(componentName, result.metrics, { ...DEFAULT_THRESHOLDS, ...thresholds }));
      }
      
      expect(result.passed).toBe(true);
    });
    
    if (!skipMemoryLeakTest) {
      it('should not have memory leaks', async () => {
        const memoryLeaks = await testMemoryLeaks(component, 50);
        const threshold = thresholds.maxMemoryLeaks || DEFAULT_THRESHOLDS.maxMemoryLeaks;
        
        expect(memoryLeaks).toBeLessThan(threshold);
      });
    }
    
    if (!skipLoadTest && loadTestFactory) {
      it('should handle increasing data sizes efficiently', async () => {
        const results = await loadTestComponent(
          (props) => loadTestFactory(props.size),
          (size) => ({ size }),
          { iterations: 5, dataSize: 100 }
        );
        
        // Check that performance doesn't degrade exponentially
        const firstRenderTime = results[0].renderTime;
        const lastRenderTime = results[results.length - 1].renderTime;
        const performanceRatio = lastRenderTime / firstRenderTime;
        
        // Should not be more than 5x slower with 5x more data
        expect(performanceRatio).toBeLessThan(5);
      });
    }
    
    it('should maintain performance during re-renders', async () => {
      const reRenderMetrics = await measureReRenderPerformance(component, component);
      const threshold = thresholds.maxReRenderTime || DEFAULT_THRESHOLDS.maxReRenderTime;
      
      expect(reRenderMetrics.reRenderTime!).toBeLessThan(threshold);
    });
  });
};

export default {
  measureRenderPerformance,
  measureReRenderPerformance,
  testMemoryLeaks,
  measureInteractionPerformance,
  loadTestComponent,
  stressTestComponent,
  benchmarkComponent,
  testPerformanceRegression,
  generatePerformanceReport,
  createPerformanceTestSuite,
  DEFAULT_THRESHOLDS
};