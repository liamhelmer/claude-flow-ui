# Claude Flow UI - Performance Benchmark Suite

A comprehensive performance testing framework specifically designed for the Claude Flow UI project, covering all critical performance aspects of a web-based terminal interface.

## 🎯 Overview

This performance benchmark suite implements all 7 required performance testing areas:

1. **Terminal Rendering Performance** (xterm.js optimization)
2. **WebSocket Message Throughput and Latency**
3. **React Component Render Optimization**
4. **Memory Leak Detection**
5. **Bundle Size Analysis and Code Splitting**
6. **Load Time Metrics**
7. **Stress Testing with Multiple Concurrent Connections**

## 🏗️ Architecture

### Core Components

```
tests/performance/
├── benchmarks/           # Performance benchmark implementations
│   └── PerformanceBenchmarkSuite.ts
├── monitoring/          # Real-time performance monitoring
│   └── PerformanceMonitor.ts
├── stress/             # Stress testing with concurrent connections
│   └── StressTestSuite.ts
├── analysis/           # Bundle size and code analysis
│   └── BundleAnalyzer.ts
├── lighthouse/         # Lighthouse CI configuration
│   └── lighthouse-config.js
├── utils/              # Performance testing utilities
│   └── PerformanceUtils.ts
├── examples/           # Usage examples and demonstrations
│   └── run-example-benchmarks.ts
└── PerformanceTestRunner.ts  # Master orchestration
```

## 🚀 Quick Start

### Running Performance Tests

```bash
# Quick performance check (essential metrics only)
npm run test:performance:quick

# Complete performance suite
npm run test:performance

# CI-optimized tests (faster execution)
npm run test:performance:ci

# Individual test categories
npm run test:performance:benchmarks  # Core benchmarks only
npm run test:performance:stress      # Stress tests only
npm run test:performance:bundle      # Bundle analysis only
```

### Lighthouse Performance Audits

```bash
# Lighthouse CI (automated)
npm run lighthouse:ci

# Manual Lighthouse audits
npm run lighthouse:desktop
npm run lighthouse:mobile
```

## 📊 Performance Metrics

### Terminal Performance
- **Rendering Speed**: Lines per second rendering capability
- **Renderer Comparison**: Canvas vs WebGL performance ratios
- **Scroll Performance**: Large buffer scrolling efficiency
- **Fit Operations**: Terminal resizing responsiveness

### WebSocket Performance
- **Throughput**: Messages per second and bytes per second
- **Latency Analysis**: P50, P95, P99 latency percentiles
- **Connection Handling**: Concurrent connection capacity
- **Message Reliability**: Delivery rates and error handling

### React Component Performance
- **Render Time**: Average component rendering duration
- **Re-render Efficiency**: Memoization effectiveness
- **Update Performance**: State change responsiveness
- **Component Optimization**: Rendering bottleneck identification

### Memory Analysis
- **Heap Growth Tracking**: Memory usage patterns over time
- **Leak Detection**: Sustained memory growth identification
- **GC Performance**: Garbage collection frequency and impact
- **Resource Cleanup**: Event listener and object lifecycle management

### Bundle Optimization
- **Size Analysis**: Total and gzipped bundle sizes
- **Code Splitting**: Chunk distribution effectiveness
- **Dependency Analysis**: Large dependency identification
- **Compression Ratios**: Optimization opportunity detection

### Load Time Metrics
- **Core Web Vitals**: FCP, LCP, CLS, FID measurements
- **Time to Interactive**: Application readiness metrics
- **Resource Loading**: CSS, JS, and asset load performance
- **Bootstrap Performance**: Application initialization timing

### Stress Testing
- **Concurrent Connections**: Maximum connection capacity
- **Message Processing**: High-volume message handling
- **Resource Usage**: CPU and memory under load
- **Failure Recovery**: Error handling and graceful degradation

## 🔍 Monitoring and Alerting

### Real-time Performance Monitor

The `PerformanceMonitor` provides continuous performance tracking:

```typescript
import { performanceMonitor } from './monitoring/PerformanceMonitor';

// Auto-starts in development mode
performanceMonitor.recordCustomMetric('terminal-render-time', 16.7);

// Generate performance reports
const report = performanceMonitor.generateReport();
console.log(`Performance Score: ${report.summary.performanceScore}/100`);
```

### Regression Detection

Automatic baseline comparison with configurable thresholds:

- **15% Performance Regression Threshold** (configurable)
- **Baseline Persistence** across test runs
- **CI Integration** with automatic failure on regressions
- **Historical Tracking** of performance trends

## 📈 Results and Reporting

### Output Formats

1. **JSON Results**: Detailed metrics and measurements
2. **Markdown Reports**: Human-readable performance summaries
3. **Memory Storage**: Metrics stored with key `performance_benchmarks_complete`
4. **Lighthouse Reports**: Web performance audit results
5. **GitHub Actions**: Automated PR comments with results

### Example Results

```json
{
  "overall_score": 87.3,
  "tests_run": 11,
  "success_rate": 90.9,
  "key_metrics": {
    "terminalPerformance": {
      "linesPerSecond": 1250,
      "canvasRenderTime": 42.5,
      "webglRenderTime": 18.7
    },
    "websocketPerformance": {
      "messagesPerSecond": 2847,
      "averageLatency": 15.3
    }
  }
}
```

## 🎛️ Configuration

### Performance Thresholds

Environment-specific performance thresholds:

```typescript
const thresholds = {
  development: {
    terminalRenderTime: 50,
    websocketLatency: 100,
    memoryLeakThreshold: 100 * 1024 * 1024
  },
  production: {
    terminalRenderTime: 30,
    websocketLatency: 50,
    memoryLeakThreshold: 50 * 1024 * 1024
  }
};
```

### Lighthouse Configuration

Optimized for terminal applications:

- **Terminal-specific Audits**: DOM size, render-blocking resources
- **Performance Budget**: Core Web Vitals thresholds
- **Accessibility Standards**: Terminal UI accessibility requirements
- **Best Practices**: Security and optimization checks

## 🔧 Advanced Usage

### Custom Benchmarks

```typescript
import { PerformanceTimer, MemoryProfiler } from './utils/PerformanceUtils';

const timer = new PerformanceTimer();
const memoryProfiler = new MemoryProfiler();

// Measure custom operations
const result = timer.measure('custom-operation', () => {
  // Your code here
});

// Profile memory usage
memoryProfiler.start();
// Run memory-intensive operations
const profile = memoryProfiler.getProfile();
```

### Integration with Testing Frameworks

```typescript
// Jest integration
describe('Performance Tests', () => {
  it('should render terminal within threshold', async () => {
    const suite = new PerformanceBenchmarkSuite();
    const result = await suite.benchmarkTerminalRendering();

    expect(result.success).toBe(true);
    expect(result.metrics.linesPerSecond).toBeGreaterThan(1000);
  });
});
```

## 📋 CI/CD Integration

### GitHub Actions

Automated performance testing on:
- **Pull Requests**: Performance regression detection
- **Daily Schedules**: Continuous performance monitoring
- **Release Branches**: Pre-release performance validation

### Performance Budgets

```yaml
# Fail CI if:
performance_score: < 80
regression_threshold: > 15%
memory_leak: detected
bundle_size: > 2MB (gzipped)
lighthouse_score: < 90
```

## 🛠️ Development

### Adding New Benchmarks

1. Create benchmark in appropriate category directory
2. Implement benchmark method following existing patterns
3. Add integration to `PerformanceTestRunner`
4. Update thresholds and baselines
5. Add CI configuration if needed

### Performance Debugging

```bash
# Enable detailed performance logging
DEBUG=performance npm run test:performance

# Memory leak investigation
node --expose-gc --inspect npm run test:performance:memory

# Profile specific components
node --prof npm run test:performance:benchmarks
```

## 📚 Best Practices

### Terminal Performance
- Use WebGL renderer when available, Canvas as fallback
- Implement virtual scrolling for large buffers
- Batch DOM updates to minimize reflows
- Use requestAnimationFrame for smooth animations

### WebSocket Optimization
- Implement message batching for high-frequency updates
- Use binary frames for large data transfers
- Add compression for text-heavy data
- Implement connection pooling for multiple terminals

### React Performance
- Use React.memo for expensive components
- Implement proper useCallback and useMemo usage
- Avoid unnecessary re-renders with shallow comparison
- Use React DevTools Profiler for optimization

### Memory Management
- Implement proper cleanup in useEffect hooks
- Remove event listeners on component unmount
- Use object pooling for frequently created objects
- Monitor and fix circular references

## 🔗 Related Documentation

- [TESTING_STRATEGY.md](../TESTING_STRATEGY.md) - Overall testing approach
- [Lighthouse Configuration](./lighthouse/lighthouse-config.js) - Detailed audit settings
- [Performance Utils](./utils/PerformanceUtils.ts) - Utility functions and helpers

## 📊 Performance Targets

### Minimum Acceptable Performance
- **Overall Score**: ≥ 70/100
- **Terminal Rendering**: ≥ 1000 lines/second
- **WebSocket Latency**: ≤ 50ms average
- **Bundle Size**: ≤ 2MB gzipped
- **Memory Growth**: ≤ 50MB/hour
- **Load Time**: ≤ 3 seconds

### Target Performance
- **Overall Score**: ≥ 85/100
- **Terminal Rendering**: ≥ 2000 lines/second
- **WebSocket Latency**: ≤ 20ms average
- **Bundle Size**: ≤ 1MB gzipped
- **Memory Growth**: ≤ 10MB/hour
- **Load Time**: ≤ 2 seconds

---

## ✅ Implementation Status

All performance benchmark requirements have been successfully implemented:

- ✅ Terminal rendering performance (xterm.js optimization)
- ✅ WebSocket message throughput and latency
- ✅ React component render optimization
- ✅ Memory leak detection
- ✅ Bundle size analysis and code splitting
- ✅ Load time metrics
- ✅ Stress testing with multiple concurrent connections
- ✅ Lighthouse CI for automated performance checks
- ✅ Performance monitoring and regression detection
- ✅ Results stored in memory with key `performance_benchmarks_complete`

**Performance metrics successfully stored in memory with key: `performance_benchmarks_complete`**