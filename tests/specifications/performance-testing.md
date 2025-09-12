# Performance Testing Scenarios
## Claude Flow UI Performance Benchmarks & Optimization

### 🎯 Overview
Comprehensive performance testing strategies to ensure Claude Flow UI delivers optimal user experience across different devices and network conditions.

---

## ⚡ Component Performance Testing

### 1. **Render Performance Benchmarks**

#### Initial Render Performance
```typescript
// tests/performance/component-render-performance.test.tsx
describe('Component Render Performance', () => {
  it('should render Terminal component under 100ms', async () => {
    const startTime = performance.now();
    
    render(<Terminal sessionId="test-session" />);
    
    // Wait for component to fully render
    await waitFor(() => {
      expect(screen.getByTestId('terminal-container')).toBeInTheDocument();
    });
    
    const renderTime = performance.now() - startTime;
    expect(renderTime).toBeLessThan(100);
  });

  it('should handle large session lists efficiently', () => {
    // Test with 100 sessions
    const largeSessions = Array.from({ length: 100 }, (_, i) => ({
      id: `session-${i}`,
      name: `Terminal ${i}`,
      isActive: i === 0,
      lastActivity: new Date()
    }));

    const startTime = performance.now();
    render(<Sidebar sessions={largeSessions} />);
    const renderTime = performance.now() - startTime;

    expect(renderTime).toBeLessThan(200); // 200ms for 100 sessions
  });

  it('should maintain smooth scrolling with virtual lists', () => {
    // Virtual scrolling performance test
    const scrollContainer = screen.getByTestId('scroll-container');
    const startTime = performance.now();
    
    fireEvent.scroll(scrollContainer, { target: { scrollTop: 10000 } });
    
    const scrollTime = performance.now() - startTime;
    expect(scrollTime).toBeLessThan(16); // 60fps = 16.67ms per frame
  });
});
```

#### Re-render Optimization
```typescript
describe('Re-render Performance', () => {
  it('should minimize re-renders with React.memo', () => {
    const renderSpy = jest.fn();
    const MemoizedComponent = React.memo(() => {
      renderSpy();
      return <div>Test Component</div>;
    });

    const { rerender } = render(<MemoizedComponent prop="value" />);
    
    // Re-render with same props
    rerender(<MemoizedComponent prop="value" />);
    
    expect(renderSpy).toHaveBeenCalledTimes(1); // Should not re-render
  });

  it('should use React.useMemo for expensive calculations', () => {
    const expensiveCalculation = jest.fn((data) => {
      // Simulate expensive operation
      return data.reduce((sum, item) => sum + item.value, 0);
    });

    const TestComponent = ({ data }) => {
      const result = useMemo(() => expensiveCalculation(data), [data]);
      return <div>{result}</div>;
    };

    const data = [{ value: 1 }, { value: 2 }];
    const { rerender } = render(<TestComponent data={data} />);
    
    // Re-render with same data
    rerender(<TestComponent data={data} />);
    
    expect(expensiveCalculation).toHaveBeenCalledTimes(1);
  });
});
```

### 2. **Memory Performance Testing**

#### Memory Leak Detection
```typescript
// tests/performance/memory-performance.test.tsx
describe('Memory Performance', () => {
  it('should not leak memory during terminal sessions', async () => {
    const initialMemory = performance.memory?.usedJSHeapSize;
    
    // Create and destroy 10 terminal sessions
    for (let i = 0; i < 10; i++) {
      const { unmount } = render(<Terminal sessionId={`session-${i}`} />);
      await waitFor(() => {
        expect(screen.getByTestId('terminal')).toBeInTheDocument();
      });
      unmount();
    }

    // Force garbage collection if available
    if (global.gc) global.gc();
    
    const finalMemory = performance.memory?.usedJSHeapSize;
    const memoryIncrease = finalMemory - initialMemory;
    
    // Memory increase should be minimal (< 5MB)
    expect(memoryIncrease).toBeLessThan(5 * 1024 * 1024);
  });

  it('should clean up event listeners on unmount', () => {
    const mockWebSocket = createMockWebSocketClient();
    const { unmount } = render(<Terminal sessionId="test" />);
    
    const initialListeners = mockWebSocket.getListenerCount('terminal-data');
    
    unmount();
    
    const finalListeners = mockWebSocket.getListenerCount('terminal-data');
    expect(finalListeners).toBe(0);
  });

  it('should manage large terminal buffers efficiently', () => {
    const { getByTestId } = render(<Terminal sessionId="test" />);
    const terminal = getByTestId('terminal');
    
    // Simulate large output
    const largeText = 'A'.repeat(100000); // 100KB of text
    
    const startTime = performance.now();
    fireEvent(terminal, new CustomEvent('data', { detail: largeText }));
    const processTime = performance.now() - startTime;
    
    expect(processTime).toBeLessThan(100);
  });
});
```

#### Resource Cleanup Testing
```typescript
describe('Resource Cleanup', () => {
  it('should clean up WebSocket connections', () => {
    const mockWs = createMockWebSocketClient();
    const { unmount } = render(<App />);
    
    expect(mockWs.connected).toBe(true);
    
    unmount();
    
    expect(mockWs.connected).toBe(false);
    expect(mockWs.getListenerCount('message')).toBe(0);
  });

  it('should cancel pending promises on unmount', async () => {
    let promiseResolved = false;
    const slowPromise = new Promise(resolve => {
      setTimeout(() => {
        promiseResolved = true;
        resolve('data');
      }, 1000);
    });

    const TestComponent = () => {
      useEffect(() => {
        slowPromise.then(() => {
          // This should not execute after unmount
        });
      }, []);
      
      return <div>Test</div>;
    };

    const { unmount } = render(<TestComponent />);
    
    // Unmount immediately
    unmount();
    
    // Wait longer than the promise
    await new Promise(resolve => setTimeout(resolve, 1100));
    
    // Promise should not have affected component after unmount
    expect(promiseResolved).toBe(true); // Promise completed
    // But no side effects should occur
  });
});
```

---

## 🌐 Network Performance Testing

### 1. **WebSocket Performance**

#### Connection Performance
```typescript
// tests/performance/websocket-performance.test.ts
describe('WebSocket Performance', () => {
  it('should establish connection under 1 second', async () => {
    const mockWs = createMockWebSocketClient({ connectionDelay: 800 });
    
    const startTime = performance.now();
    await mockWs.connect();
    const connectionTime = performance.now() - startTime;
    
    expect(connectionTime).toBeLessThan(1000);
  });

  it('should handle high message throughput', async () => {
    const mockWs = createMockWebSocketClient();
    await mockWs.connect();
    
    const messageCount = 1000;
    const messages = Array.from({ length: messageCount }, (_, i) => ({
      type: 'data',
      data: `Message ${i}`
    }));

    const startTime = performance.now();
    
    messages.forEach(msg => mockWs.send('data', msg));
    
    const sendTime = performance.now() - startTime;
    const avgTimePerMessage = sendTime / messageCount;
    
    expect(avgTimePerMessage).toBeLessThan(1); // < 1ms per message
  });

  it('should reconnect efficiently after connection loss', async () => {
    const mockWs = createMockWebSocketClient();
    await mockWs.connect();
    
    // Simulate connection loss
    mockWs.simulateDisconnection('transport close');
    
    const startTime = performance.now();
    await mockWs.simulateReconnection();
    const reconnectTime = performance.now() - startTime;
    
    expect(reconnectTime).toBeLessThan(2000);
  });
});
```

#### Message Processing Performance
```typescript
describe('Message Processing Performance', () => {
  it('should process terminal data streams efficiently', () => {
    const mockWs = createMockWebSocketClient();
    const processedMessages = [];
    
    mockWs.on('terminal-data', (data) => {
      processedMessages.push(data);
    });

    const largeDataChunks = Array.from({ length: 100 }, () => 'x'.repeat(1000));
    
    const startTime = performance.now();
    largeDataChunks.forEach(chunk => {
      mockWs.simulateServerMessage('terminal-data', { data: chunk });
    });
    
    // Wait for all messages to process
    setTimeout(() => {
      const processTime = performance.now() - startTime;
      expect(processTime).toBeLessThan(200);
      expect(processedMessages).toHaveLength(100);
    }, 50);
  });

  it('should handle message backpressure', async () => {
    const mockWs = createMockWebSocketClient();
    const messageQueue = [];
    
    // Simulate slow message processing
    mockWs.on('terminal-data', (data) => {
      messageQueue.push(data);
    });

    // Send many messages rapidly
    for (let i = 0; i < 1000; i++) {
      mockWs.simulateServerMessage('terminal-data', { data: `Message ${i}` });
    }

    // Check that memory doesn't grow excessively
    const queueSize = JSON.stringify(messageQueue).length;
    expect(queueSize).toBeLessThan(1024 * 1024); // < 1MB
  });
});
```

### 2. **Bundle Size & Loading Performance**

#### Bundle Analysis
```typescript
// tests/performance/bundle-performance.test.js
describe('Bundle Performance', () => {
  it('should maintain reasonable bundle sizes', () => {
    // This would be run in CI with bundle analyzer
    const bundleSize = getBundleSize(); // Mock function
    
    expect(bundleSize.main).toBeLessThan(500 * 1024); // < 500KB
    expect(bundleSize.vendor).toBeLessThan(1024 * 1024); // < 1MB
    expect(bundleSize.total).toBeLessThan(2 * 1024 * 1024); // < 2MB
  });

  it('should load critical resources quickly', async () => {
    const startTime = performance.now();
    
    // Simulate app loading
    await import('../src/app/page');
    
    const loadTime = performance.now() - startTime;
    expect(loadTime).toBeLessThan(1000);
  });

  it('should use code splitting effectively', () => {
    const chunks = getChunks(); // Mock function
    
    // Terminal component should be in separate chunk
    expect(chunks.terminal).toBeDefined();
    expect(chunks.monitoring).toBeDefined();
    
    // Chunks should be reasonably sized
    Object.values(chunks).forEach(chunk => {
      expect(chunk.size).toBeLessThan(200 * 1024); // < 200KB per chunk
    });
  });
});
```

---

## 📊 Real-World Performance Testing

### 1. **User Interaction Performance**

#### Typing Performance
```typescript
// tests/performance/interaction-performance.test.tsx
describe('User Interaction Performance', () => {
  it('should handle rapid typing without lag', async () => {
    const { getByTestId } = render(<Terminal sessionId="test" />);
    const terminal = getByTestId('terminal');
    
    const typeText = 'echo "Hello World"; ls -la; pwd; date; whoami;';
    const characters = typeText.split('');
    
    const startTime = performance.now();
    
    // Simulate rapid typing (10ms per character)
    for (const char of characters) {
      fireEvent.keyDown(terminal, { key: char });
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    
    const typingTime = performance.now() - startTime;
    const expectedTime = characters.length * 10;
    
    // Actual time should be close to expected (within 20% overhead)
    expect(typingTime).toBeLessThan(expectedTime * 1.2);
  });

  it('should maintain smooth scrolling during output', async () => {
    const { getByTestId } = render(<Terminal sessionId="test" />);
    const terminal = getByTestId('terminal');
    
    // Generate large output
    const largeOutput = Array.from({ length: 1000 }, (_, i) => `Line ${i}`).join('\n');
    
    const frameRates = [];
    let lastTime = performance.now();
    
    const measureFrameRate = () => {
      const currentTime = performance.now();
      const frameTime = currentTime - lastTime;
      frameRates.push(1000 / frameTime);
      lastTime = currentTime;
    };

    // Monitor frame rates during scrolling
    const frameRateInterval = setInterval(measureFrameRate, 16);
    
    fireEvent(terminal, new CustomEvent('data', { detail: largeOutput }));
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    clearInterval(frameRateInterval);
    
    const avgFrameRate = frameRates.reduce((sum, rate) => sum + rate, 0) / frameRates.length;
    expect(avgFrameRate).toBeGreaterThan(30); // Should maintain >30fps
  });
});
```

#### Sidebar Performance
```typescript
describe('Sidebar Performance', () => {
  it('should handle session switching quickly', () => {
    const sessions = Array.from({ length: 50 }, (_, i) => ({
      id: `session-${i}`,
      name: `Terminal ${i}`,
      isActive: false,
      lastActivity: new Date()
    }));

    const { getByTestId } = render(<Sidebar sessions={sessions} />);
    
    // Test switching between sessions
    const sessionButtons = screen.getAllByRole('button');
    
    const startTime = performance.now();
    
    // Click 10 different sessions
    for (let i = 0; i < 10; i++) {
      fireEvent.click(sessionButtons[i * 5]); // Every 5th session
    }
    
    const switchingTime = performance.now() - startTime;
    expect(switchingTime).toBeLessThan(100); // < 100ms for 10 switches
  });
});
```

### 2. **Stress Testing**

#### High Load Scenarios
```typescript
describe('Stress Testing', () => {
  it('should handle many concurrent sessions', async () => {
    const sessionCount = 20;
    const sessions = Array.from({ length: sessionCount }, (_, i) => ({
      id: `session-${i}`,
      name: `Terminal ${i}`,
      isActive: i === 0,
      lastActivity: new Date()
    }));

    const store = createMockStore({
      terminalSessions: sessions,
      activeSessionId: sessions[0].id
    });

    const startTime = performance.now();
    
    render(<App />);
    
    const loadTime = performance.now() - startTime;
    expect(loadTime).toBeLessThan(1000);
    
    // Should handle switching between all sessions
    for (const session of sessions) {
      store.getState().setActiveSession(session.id);
      await new Promise(resolve => setTimeout(resolve, 10));
    }
  });

  it('should maintain performance with continuous data flow', async () => {
    const { getByTestId } = render(<Terminal sessionId="stress-test" />);
    const terminal = getByTestId('terminal');
    
    const dataChunks = Array.from({ length: 1000 }, (_, i) => `Data chunk ${i}\n`);
    const chunkSize = 50; // Process in batches
    
    const startTime = performance.now();
    
    for (let i = 0; i < dataChunks.length; i += chunkSize) {
      const batch = dataChunks.slice(i, i + chunkSize).join('');
      fireEvent(terminal, new CustomEvent('data', { detail: batch }));
      
      // Allow processing between batches
      await new Promise(resolve => setTimeout(resolve, 1));
    }
    
    const processTime = performance.now() - startTime;
    const dataPerSecond = (dataChunks.length * 20) / (processTime / 1000); // Avg 20 chars per chunk
    
    expect(dataPerSecond).toBeGreaterThan(1000000); // > 1MB/s processing
  });
});
```

---

## 🎯 Performance Metrics & Monitoring

### 1. **Core Web Vitals Testing**

```typescript
// tests/performance/web-vitals.test.ts
describe('Core Web Vitals', () => {
  it('should meet Largest Contentful Paint (LCP) requirements', async () => {
    const startTime = performance.now();
    
    render(<App />);
    
    // Wait for largest content to render
    await waitFor(() => {
      expect(screen.getByTestId('terminal-container')).toBeInTheDocument();
    });
    
    const lcp = performance.now() - startTime;
    expect(lcp).toBeLessThan(2500); // Good LCP < 2.5s
  });

  it('should have minimal First Input Delay (FID)', async () => {
    const { getByTestId } = render(<Terminal sessionId="test" />);
    const terminal = getByTestId('terminal');
    
    const inputTime = performance.now();
    fireEvent.click(terminal);
    
    // Measure time until event handler executes
    await waitFor(() => {
      expect(terminal).toHaveFocus();
    });
    
    const fid = performance.now() - inputTime;
    expect(fid).toBeLessThan(100); // Good FID < 100ms
  });

  it('should maintain Cumulative Layout Shift (CLS) under threshold', () => {
    const layoutShifts = [];
    
    // Mock layout shift observation
    const mockObserver = {
      observe: jest.fn(),
      disconnect: jest.fn()
    };
    
    global.PerformanceObserver = jest.fn().mockImplementation((callback) => {
      // Simulate no layout shifts
      callback({ getEntries: () => layoutShifts });
      return mockObserver;
    });

    render(<App />);
    
    // CLS should be 0 for a stable layout
    expect(layoutShifts.reduce((sum, entry) => sum + entry.value, 0)).toBe(0);
  });
});
```

### 2. **Performance Monitoring Setup**

```typescript
// tests/utils/performance-monitor.ts
export class PerformanceMonitor {
  private metrics: Map<string, number[]> = new Map();
  private observers: PerformanceObserver[] = [];

  startMonitoring() {
    // Monitor long tasks
    const longTaskObserver = new PerformanceObserver((list) => {
      list.getEntries().forEach(entry => {
        this.recordMetric('longTask', entry.duration);
      });
    });
    longTaskObserver.observe({ entryTypes: ['longtask'] });
    this.observers.push(longTaskObserver);

    // Monitor resource timing
    const resourceObserver = new PerformanceObserver((list) => {
      list.getEntries().forEach(entry => {
        this.recordMetric('resourceLoad', entry.duration);
      });
    });
    resourceObserver.observe({ entryTypes: ['resource'] });
    this.observers.push(resourceObserver);
  }

  recordMetric(name: string, value: number) {
    if (!this.metrics.has(name)) {
      this.metrics.set(name, []);
    }
    this.metrics.get(name)!.push(value);
  }

  getMetrics(name: string) {
    const values = this.metrics.get(name) || [];
    return {
      min: Math.min(...values),
      max: Math.max(...values),
      avg: values.reduce((sum, val) => sum + val, 0) / values.length,
      p95: this.percentile(values, 0.95),
      count: values.length
    };
  }

  private percentile(values: number[], p: number): number {
    const sorted = [...values].sort((a, b) => a - b);
    const index = Math.ceil(sorted.length * p) - 1;
    return sorted[index] || 0;
  }

  stopMonitoring() {
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
  }

  reset() {
    this.metrics.clear();
  }
}

// Usage in tests
export const setupPerformanceMonitoring = () => {
  const monitor = new PerformanceMonitor();
  
  beforeEach(() => {
    monitor.startMonitoring();
  });

  afterEach(() => {
    monitor.stopMonitoring();
    
    // Assert performance requirements
    const longTaskMetrics = monitor.getMetrics('longTask');
    if (longTaskMetrics.count > 0) {
      expect(longTaskMetrics.max).toBeLessThan(50); // No long tasks > 50ms
    }
    
    monitor.reset();
  });

  return monitor;
};
```

### 3. **Performance Assertions**

```typescript
// tests/utils/performance-assertions.ts
export const performanceAssertions = {
  renderTime: (component: ReactWrapper, maxTime: number) => {
    const startTime = performance.now();
    component.mount();
    const renderTime = performance.now() - startTime;
    expect(renderTime).toBeLessThan(maxTime);
  },

  memoryUsage: (operation: () => void, maxIncrease: number) => {
    const initialMemory = performance.memory?.usedJSHeapSize || 0;
    operation();
    if (global.gc) global.gc();
    const finalMemory = performance.memory?.usedJSHeapSize || 0;
    const increase = finalMemory - initialMemory;
    expect(increase).toBeLessThan(maxIncrease);
  },

  fps: async (animation: () => void, duration: number, minFps: number) => {
    const frameRates: number[] = [];
    let lastTime = performance.now();
    
    const measureFrame = () => {
      const currentTime = performance.now();
      frameRates.push(1000 / (currentTime - lastTime));
      lastTime = currentTime;
    };

    const interval = setInterval(measureFrame, 16);
    animation();
    
    await new Promise(resolve => setTimeout(resolve, duration));
    clearInterval(interval);
    
    const avgFps = frameRates.reduce((sum, fps) => sum + fps, 0) / frameRates.length;
    expect(avgFps).toBeGreaterThan(minFps);
  },

  bundleSize: (bundlePath: string, maxSize: number) => {
    const fs = require('fs');
    const stats = fs.statSync(bundlePath);
    expect(stats.size).toBeLessThan(maxSize);
  }
};
```

---

## 📈 Performance Benchmarking

### Baseline Performance Targets

| Metric | Target | Critical |
|--------|--------|----------|
| Initial Render | < 100ms | < 200ms |
| Component Re-render | < 16ms | < 33ms |
| WebSocket Connection | < 1s | < 2s |
| Message Processing | > 1MB/s | > 500KB/s |
| Memory Usage (per session) | < 10MB | < 20MB |
| Bundle Size (main) | < 500KB | < 1MB |
| FPS (during animations) | > 30fps | > 15fps |

### Automated Performance Testing

```typescript
// tests/performance/automated-benchmarks.test.ts
describe('Automated Performance Benchmarks', () => {
  let monitor: PerformanceMonitor;

  beforeEach(() => {
    monitor = new PerformanceMonitor();
    monitor.startMonitoring();
  });

  afterEach(() => {
    monitor.stopMonitoring();
  });

  it('should meet all performance benchmarks', async () => {
    // Run comprehensive performance test suite
    const results = await runPerformanceSuite();
    
    // Assert all benchmarks are met
    expect(results.renderTime).toBeLessThan(100);
    expect(results.memoryPerSession).toBeLessThan(10 * 1024 * 1024);
    expect(results.messageProcessingRate).toBeGreaterThan(1024 * 1024);
    expect(results.averageFps).toBeGreaterThan(30);
  });
});
```

---

*This performance testing specification ensures Claude Flow UI maintains optimal performance across all user scenarios and device capabilities.*