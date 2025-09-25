/**
 * Real-time Performance Monitoring System
 *
 * Monitors application performance in real-time and detects regressions
 * automatically. Integrates with the benchmark suite for continuous monitoring.
 */

import { EventEmitter } from 'events';
import { performance, PerformanceObserver } from 'perf_hooks';

interface PerformanceAlert {
  id: string;
  timestamp: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  metric: string;
  currentValue: number;
  threshold: number;
  message: string;
  context?: Record<string, any>;
}

interface MonitoringConfig {
  sampleInterval: number; // milliseconds
  alertThresholds: Record<string, number>;
  enableRealTimeAlerts: boolean;
  enableMemoryTracking: boolean;
  enableNetworkTracking: boolean;
  enableRenderTracking: boolean;
  maxHistorySize: number;
}

interface PerformanceSnapshot {
  timestamp: number;
  memory: NodeJS.MemoryUsage;
  timing: Record<string, number>;
  custom: Record<string, number>;
  gc?: any;
  network?: Record<string, number>;
}

export class PerformanceMonitor extends EventEmitter {
  private config: MonitoringConfig;
  private isMonitoring: boolean = false;
  private snapshots: PerformanceSnapshot[] = [];
  private alerts: PerformanceAlert[] = [];
  private observers: PerformanceObserver[] = [];
  private intervals: NodeJS.Timeout[] = [];
  private lastGCTime: number = 0;
  private customMetrics: Map<string, number[]> = new Map();
  private baselines: Map<string, number> = new Map();

  constructor(config: Partial<MonitoringConfig> = {}) {
    super();

    this.config = {
      sampleInterval: 1000, // 1 second
      alertThresholds: {
        memoryGrowthRate: 50 * 1024 * 1024, // 50MB/min
        heapUsagePercent: 80, // 80% of heap
        gcFrequency: 10, // GCs per minute
        eventLoopLag: 100, // 100ms
        cpuUsage: 80, // 80%
        renderTime: 16.67, // 60fps = 16.67ms per frame
        networkLatency: 1000, // 1s
        errorRate: 0.05, // 5%
      },
      enableRealTimeAlerts: true,
      enableMemoryTracking: true,
      enableNetworkTracking: true,
      enableRenderTracking: true,
      maxHistorySize: 1000,
      ...config
    };

    this.setupPerformanceObservers();
    this.loadBaselines();
  }

  private setupPerformanceObservers(): void {
    // Navigation timing observer
    if (typeof PerformanceObserver !== 'undefined') {
      const navigationObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.entryType === 'navigation') {
            this.recordCustomMetric('navigationTiming', entry.duration);
          }
        }
      });

      try {
        navigationObserver.observe({ type: 'navigation', buffered: true });
        this.observers.push(navigationObserver);
      } catch (e) {
        // Navigation timing not available in Node.js
      }

      // Paint timing observer
      const paintObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.name === 'first-contentful-paint') {
            this.recordCustomMetric('firstContentfulPaint', entry.startTime);
          } else if (entry.name === 'first-paint') {
            this.recordCustomMetric('firstPaint', entry.startTime);
          }
        }
      });

      try {
        paintObserver.observe({ type: 'paint', buffered: true });
        this.observers.push(paintObserver);
      } catch (e) {
        // Paint timing not available in Node.js
      }

      // Long task observer
      const longTaskObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          if (entry.duration > 50) { // Tasks longer than 50ms
            this.recordCustomMetric('longTaskDuration', entry.duration);
            this.checkAlert('longTask', entry.duration, 50, 'high');
          }
        }
      });

      try {
        longTaskObserver.observe({ type: 'longtask' });
        this.observers.push(longTaskObserver);
      } catch (e) {
        // Long task timing not available in Node.js
      }
    }
  }

  private loadBaselines(): void {
    try {
      const fs = require('fs');
      const baselinesPath = '/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/baselines.json';
      if (fs.existsSync(baselinesPath)) {
        const data = JSON.parse(fs.readFileSync(baselinesPath, 'utf8'));
        for (const [key, value] of Object.entries(data)) {
          if (typeof value === 'object' && value !== null) {
            // Extract numeric values from nested objects
            for (const [subKey, subValue] of Object.entries(value as any)) {
              if (typeof subValue === 'number') {
                this.baselines.set(`${key}.${subKey}`, subValue);
              }
            }
          }
        }
      }
    } catch (error) {
      console.warn('Could not load performance baselines for monitoring:', error);
    }
  }

  startMonitoring(): void {
    if (this.isMonitoring) {
      return;
    }

    console.log('🔍 Starting performance monitoring...');
    this.isMonitoring = true;

    // Main monitoring loop
    const monitoringInterval = setInterval(() => {
      this.captureSnapshot();
    }, this.config.sampleInterval);

    this.intervals.push(monitoringInterval);

    // Memory monitoring
    if (this.config.enableMemoryTracking) {
      const memoryInterval = setInterval(() => {
        this.checkMemoryHealth();
      }, this.config.sampleInterval * 2); // Every 2 seconds

      this.intervals.push(memoryInterval);
    }

    // GC monitoring
    if (global.gc) {
      const gcInterval = setInterval(() => {
        this.monitorGarbageCollection();
      }, this.config.sampleInterval);

      this.intervals.push(gcInterval);
    }

    // Event loop lag monitoring
    const eventLoopInterval = setInterval(() => {
      this.measureEventLoopLag();
    }, this.config.sampleInterval);

    this.intervals.push(eventLoopInterval);

    this.emit('monitoring-started');
  }

  stopMonitoring(): void {
    if (!this.isMonitoring) {
      return;
    }

    console.log('🛑 Stopping performance monitoring...');
    this.isMonitoring = false;

    // Clear all intervals
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals = [];

    // Disconnect observers
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];

    this.emit('monitoring-stopped');
  }

  private captureSnapshot(): void {
    const snapshot: PerformanceSnapshot = {
      timestamp: Date.now(),
      memory: process.memoryUsage(),
      timing: {},
      custom: {},
    };

    // Add performance timing data
    if (typeof performance !== 'undefined' && performance.now) {
      snapshot.timing.performanceNow = performance.now();
    }

    // Add custom metrics
    for (const [key, values] of this.customMetrics) {
      if (values.length > 0) {
        snapshot.custom[key] = values[values.length - 1]; // Latest value
      }
    }

    // Add GC information if available
    if (global.gc && typeof (global as any).process?.memoryUsage === 'function') {
      try {
        const beforeGC = process.memoryUsage();
        global.gc();
        const afterGC = process.memoryUsage();

        snapshot.gc = {
          beforeHeapUsed: beforeGC.heapUsed,
          afterHeapUsed: afterGC.heapUsed,
          freed: beforeGC.heapUsed - afterGC.heapUsed,
        };
      } catch (e) {
        // GC failed or not available
      }
    }

    this.snapshots.push(snapshot);

    // Maintain history size limit
    if (this.snapshots.length > this.config.maxHistorySize) {
      this.snapshots = this.snapshots.slice(-this.config.maxHistorySize);
    }

    this.emit('snapshot-captured', snapshot);
  }

  private checkMemoryHealth(): void {
    if (this.snapshots.length < 2) return;

    const current = this.snapshots[this.snapshots.length - 1];
    const previous = this.snapshots[this.snapshots.length - 2];

    const memoryGrowth = current.memory.heapUsed - previous.memory.heapUsed;
    const timeDiff = current.timestamp - previous.timestamp;
    const growthRate = (memoryGrowth / timeDiff) * 60000; // Per minute

    // Check growth rate
    this.checkAlert('memoryGrowthRate', growthRate, this.config.alertThresholds.memoryGrowthRate, 'high');

    // Check heap usage percentage
    const heapUsagePercent = (current.memory.heapUsed / current.memory.heapTotal) * 100;
    this.checkAlert('heapUsagePercent', heapUsagePercent, this.config.alertThresholds.heapUsagePercent, 'medium');

    // Check for memory leaks (sustained growth)
    if (this.snapshots.length >= 10) {
      const last10 = this.snapshots.slice(-10);
      const avgGrowth = last10.reduce((sum, snapshot, i) => {
        if (i === 0) return sum;
        return sum + (snapshot.memory.heapUsed - last10[i - 1].memory.heapUsed);
      }, 0) / 9;

      if (avgGrowth > 1024 * 1024) { // 1MB average growth over 10 samples
        this.createAlert('memory-leak-suspected', 'high', 'memory', 'heapUsed',
          current.memory.heapUsed, avgGrowth,
          'Sustained memory growth detected - possible memory leak');
      }
    }
  }

  private monitorGarbageCollection(): void {
    const now = performance.now();

    if (this.lastGCTime > 0) {
      const timeSinceLastGC = now - this.lastGCTime;
      const gcFrequency = 60000 / timeSinceLastGC; // GCs per minute

      this.checkAlert('gcFrequency', gcFrequency, this.config.alertThresholds.gcFrequency, 'medium');
    }

    this.lastGCTime = now;
  }

  private measureEventLoopLag(): void {
    const start = performance.now();

    setImmediate(() => {
      const lag = performance.now() - start;
      this.recordCustomMetric('eventLoopLag', lag);
      this.checkAlert('eventLoopLag', lag, this.config.alertThresholds.eventLoopLag, 'high');
    });
  }

  recordCustomMetric(name: string, value: number): void {
    if (!this.customMetrics.has(name)) {
      this.customMetrics.set(name, []);
    }

    const values = this.customMetrics.get(name)!;
    values.push(value);

    // Keep only recent values
    if (values.length > 100) {
      values.splice(0, values.length - 100);
    }

    // Check against baseline if available
    const baselineKey = `${name}`;
    const baseline = this.baselines.get(baselineKey);

    if (baseline && value > baseline * 1.5) { // 50% regression threshold
      this.createAlert(`${name}-regression`, 'medium', 'performance', name,
        value, baseline, `Performance regression detected in ${name}`);
    }

    this.emit('custom-metric-recorded', { name, value });
  }

  private checkAlert(metric: string, value: number, threshold: number, severity: PerformanceAlert['severity']): void {
    if (value > threshold) {
      this.createAlert(metric, severity, 'performance', metric, value, threshold,
        `${metric} exceeded threshold: ${value.toFixed(2)} > ${threshold}`);
    }
  }

  private createAlert(
    id: string,
    severity: PerformanceAlert['severity'],
    category: string,
    metric: string,
    currentValue: number,
    threshold: number,
    message: string,
    context?: Record<string, any>
  ): void {
    const alert: PerformanceAlert = {
      id,
      timestamp: Date.now(),
      severity,
      category,
      metric,
      currentValue,
      threshold,
      message,
      context
    };

    this.alerts.push(alert);

    // Limit alert history
    if (this.alerts.length > 1000) {
      this.alerts = this.alerts.slice(-1000);
    }

    if (this.config.enableRealTimeAlerts) {
      console.warn(`⚠️  Performance Alert [${severity.toUpperCase()}]: ${message}`);
    }

    this.emit('alert-created', alert);
  }

  getSnapshots(limit?: number): PerformanceSnapshot[] {
    if (limit) {
      return this.snapshots.slice(-limit);
    }
    return [...this.snapshots];
  }

  getAlerts(severity?: PerformanceAlert['severity'], limit?: number): PerformanceAlert[] {
    let alerts = [...this.alerts];

    if (severity) {
      alerts = alerts.filter(alert => alert.severity === severity);
    }

    if (limit) {
      alerts = alerts.slice(-limit);
    }

    return alerts;
  }

  getMetricHistory(metric: string, limit?: number): number[] {
    const values = this.customMetrics.get(metric) || [];

    if (limit) {
      return values.slice(-limit);
    }

    return [...values];
  }

  generateReport(): {
    summary: Record<string, any>;
    alerts: PerformanceAlert[];
    metrics: Record<string, any>;
    recommendations: string[];
  } {
    const now = Date.now();
    const recentSnapshots = this.snapshots.slice(-10);
    const recentAlerts = this.alerts.filter(alert => now - alert.timestamp < 300000); // Last 5 minutes

    // Calculate summary statistics
    const summary = {
      monitoringDuration: this.snapshots.length > 0
        ? now - this.snapshots[0].timestamp
        : 0,
      totalSnapshots: this.snapshots.length,
      totalAlerts: this.alerts.length,
      recentAlerts: recentAlerts.length,
      criticalAlerts: this.alerts.filter(a => a.severity === 'critical').length,
      averageMemoryUsage: recentSnapshots.length > 0
        ? recentSnapshots.reduce((sum, s) => sum + s.memory.heapUsed, 0) / recentSnapshots.length
        : 0,
      memoryGrowthTrend: this.calculateMemoryTrend(),
      performanceScore: this.calculatePerformanceScore(),
    };

    // Collect metrics
    const metrics: Record<string, any> = {};
    for (const [name, values] of this.customMetrics) {
      if (values.length > 0) {
        metrics[name] = {
          current: values[values.length - 1],
          average: values.reduce((sum, v) => sum + v, 0) / values.length,
          min: Math.min(...values),
          max: Math.max(...values),
          count: values.length,
        };
      }
    }

    // Generate recommendations
    const recommendations = this.generateRecommendations(recentAlerts);

    return {
      summary,
      alerts: recentAlerts,
      metrics,
      recommendations
    };
  }

  private calculateMemoryTrend(): string {
    if (this.snapshots.length < 10) return 'insufficient-data';

    const recent = this.snapshots.slice(-10);
    const first = recent[0].memory.heapUsed;
    const last = recent[recent.length - 1].memory.heapUsed;
    const change = ((last - first) / first) * 100;

    if (change > 10) return 'increasing';
    if (change < -10) return 'decreasing';
    return 'stable';
  }

  private calculatePerformanceScore(): number {
    // Simple scoring algorithm based on recent alerts and metrics
    let score = 100;

    const recentAlerts = this.alerts.filter(alert =>
      Date.now() - alert.timestamp < 300000 // Last 5 minutes
    );

    score -= recentAlerts.filter(a => a.severity === 'critical').length * 20;
    score -= recentAlerts.filter(a => a.severity === 'high').length * 10;
    score -= recentAlerts.filter(a => a.severity === 'medium').length * 5;
    score -= recentAlerts.filter(a => a.severity === 'low').length * 2;

    return Math.max(0, Math.min(100, score));
  }

  private generateRecommendations(alerts: PerformanceAlert[]): string[] {
    const recommendations: string[] = [];
    const alertTypes = new Set(alerts.map(a => a.metric));

    if (alertTypes.has('memoryGrowthRate')) {
      recommendations.push('Consider implementing object pooling to reduce garbage collection pressure');
      recommendations.push('Review code for potential memory leaks in event listeners or closures');
    }

    if (alertTypes.has('eventLoopLag')) {
      recommendations.push('Break down long-running operations into smaller chunks');
      recommendations.push('Use setTimeout or setImmediate to yield control back to the event loop');
    }

    if (alertTypes.has('gcFrequency')) {
      recommendations.push('Optimize object allocation patterns to reduce GC frequency');
      recommendations.push('Consider using larger batch sizes to reduce allocation overhead');
    }

    if (alertTypes.has('longTask')) {
      recommendations.push('Profile long tasks and break them into smaller operations');
      recommendations.push('Use Web Workers for CPU-intensive operations if running in browser');
    }

    return recommendations;
  }

  saveReport(): string {
    try {
      const fs = require('fs');
      const report = this.generateReport();
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const reportPath = `/Users/liam.helmer/repos/liamhelmer/claude-flow-ui/tests/performance/monitoring/performance-report-${timestamp}.json`;

      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
      console.log(`📄 Performance report saved to: ${reportPath}`);

      return reportPath;
    } catch (error) {
      console.error('Could not save performance report:', error);
      throw error;
    }
  }

  dispose(): void {
    this.stopMonitoring();
    this.removeAllListeners();
    this.snapshots = [];
    this.alerts = [];
    this.customMetrics.clear();
  }
}

// Export singleton instance for global use
export const performanceMonitor = new PerformanceMonitor();

// Auto-start monitoring in development
if (process.env.NODE_ENV === 'development' || process.env.ENABLE_PERFORMANCE_MONITORING === 'true') {
  performanceMonitor.startMonitoring();
}