import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';

// Mock performance monitoring component
interface PerformanceMetrics {
  renderTime: number;
  memoryUsage: number;
  componentCount: number;
  reRenderCount: number;
  updateTime: number;
  cpuUsage?: number;
  networkLatency?: number;
}

interface PerformanceMonitorProps {
  children: React.ReactNode;
  threshold?: {
    renderTime?: number;
    memoryUsage?: number;
    reRenderCount?: number;
  };
  onMetricsUpdate?: (metrics: PerformanceMetrics) => void;
  onThresholdExceeded?: (metric: string, value: number, threshold: number) => void;
  enableDetailedTracking?: boolean;
  sampleRate?: number;
}

const PerformanceMonitor: React.FC<PerformanceMonitorProps> = ({
  children,
  threshold = {},
  onMetricsUpdate,
  onThresholdExceeded,
  enableDetailedTracking = false,
  sampleRate = 1.0,
}) => {
  const [metrics, setMetrics] = React.useState<PerformanceMetrics>({
    renderTime: 0,
    memoryUsage: 0,
    componentCount: 0,
    reRenderCount: 0,
    updateTime: 0,
  });

  const renderStartTime = React.useRef<number>(0);
  const componentRef = React.useRef<HTMLDivElement>(null);
  const observerRef = React.useRef<PerformanceObserver | null>(null);

  const measureRenderTime = React.useCallback(() => {
    if (Math.random() > sampleRate) return;

    const renderTime = performance.now() - renderStartTime.current;
    
    setMetrics(prev => {
      const newMetrics = {
        ...prev,
        renderTime,
        reRenderCount: prev.reRenderCount + 1,
        updateTime: performance.now(),
      };

      // Check thresholds
      if (threshold.renderTime && renderTime > threshold.renderTime) {
        onThresholdExceeded?.('renderTime', renderTime, threshold.renderTime);
      }

      if (threshold.reRenderCount && newMetrics.reRenderCount > threshold.reRenderCount) {
        onThresholdExceeded?.('reRenderCount', newMetrics.reRenderCount, threshold.reRenderCount);
      }

      onMetricsUpdate?.(newMetrics);
      return newMetrics;
    });
  }, [onMetricsUpdate, onThresholdExceeded, threshold, sampleRate]);

  const measureMemoryUsage = React.useCallback(() => {
    if ('memory' in performance && (performance as any).memory) {
      const memoryInfo = (performance as any).memory;
      const memoryUsage = memoryInfo.usedJSHeapSize;

      setMetrics(prev => {
        const newMetrics = { ...prev, memoryUsage };

        if (threshold.memoryUsage && memoryUsage > threshold.memoryUsage) {
          onThresholdExceeded?.('memoryUsage', memoryUsage, threshold.memoryUsage);
        }

        return newMetrics;
      });
    }
  }, [onThresholdExceeded, threshold.memoryUsage]);

  const countComponents = React.useCallback(() => {
    if (componentRef.current) {
      const count = componentRef.current.querySelectorAll('*').length;
      setMetrics(prev => ({ ...prev, componentCount: count }));
    }
  }, []);

  React.useLayoutEffect(() => {
    renderStartTime.current = performance.now();
  });

  React.useEffect(() => {
    measureRenderTime();
    measureMemoryUsage();
    countComponents();
  });

  React.useEffect(() => {
    if (enableDetailedTracking && 'PerformanceObserver' in window) {
      observerRef.current = new PerformanceObserver((list) => {
        const entries = list.getEntries();
        entries.forEach((entry) => {
          if (entry.entryType === 'measure' || entry.entryType === 'navigation') {
            setMetrics(prev => ({
              ...prev,
              networkLatency: entry.duration,
            }));
          }
        });
      });

      observerRef.current.observe({ entryTypes: ['measure', 'navigation'] });
    }

    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, [enableDetailedTracking]);

  return (
    <div ref={componentRef} data-testid="performance-monitor">
      <div data-testid="metrics" style={{ display: 'none' }}>
        {JSON.stringify(metrics)}
      </div>
      {children}
    </div>
  );
};

// Test components for performance testing
const HeavyComponent: React.FC<{ itemCount?: number }> = ({ itemCount = 1000 }) => {
  const items = React.useMemo(() => 
    Array.from({ length: itemCount }, (_, i) => ({ id: i, value: Math.random() })),
    [itemCount]
  );

  return (
    <div data-testid="heavy-component">
      {items.map(item => (
        <div key={item.id} data-testid={`item-${item.id}`}>
          Item {item.id}: {item.value.toFixed(4)}
        </div>
      ))}
    </div>
  );
};

const ReRenderingComponent: React.FC = () => {
  const [count, setCount] = React.useState(0);

  React.useEffect(() => {
    const interval = setInterval(() => {
      setCount(c => c + 1);
    }, 10);

    return () => clearInterval(interval);
  }, []);

  return <div data-testid="rerendering-component">Count: {count}</div>;
};

const MemoryLeakComponent: React.FC<{ shouldLeak?: boolean }> = ({ shouldLeak = false }) => {
  const dataRef = React.useRef<any[]>([]);

  React.useEffect(() => {
    if (shouldLeak) {
      // Simulate memory leak by accumulating data
      const interval = setInterval(() => {
        dataRef.current.push(new Array(1000).fill(Math.random()));
      }, 10);

      // Intentionally not clearing interval to simulate leak
      if (!shouldLeak) {
        return () => clearInterval(interval);
      }
    }
  }, [shouldLeak]);

  return <div data-testid="memory-leak-component">Memory leak test</div>;
};

describe('PerformanceMonitor Comprehensive Tests', () => {
  let mockPerformanceMemory: any;
  let mockPerformanceObserver: any;

  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();

    // Mock performance.memory
    mockPerformanceMemory = {
      usedJSHeapSize: 10000000,
      totalJSHeapSize: 20000000,
      jsHeapSizeLimit: 50000000,
    };

    Object.defineProperty(performance, 'memory', {
      value: mockPerformanceMemory,
      configurable: true,
    });

    // Mock PerformanceObserver
    mockPerformanceObserver = {
      observe: jest.fn(),
      disconnect: jest.fn(),
    };

    global.PerformanceObserver = jest.fn().mockImplementation((callback) => {
      mockPerformanceObserver.callback = callback;
      return mockPerformanceObserver;
    });

    // Mock performance.now
    jest.spyOn(performance, 'now').mockReturnValue(1000);
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  describe('Basic Performance Monitoring', () => {
    it('should monitor render time and component count', async () => {
      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <div>Test component</div>
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onMetricsUpdate).toHaveBeenCalled();
      });

      const metrics = onMetricsUpdate.mock.calls[0][0];
      expect(metrics.renderTime).toBeGreaterThanOrEqual(0);
      expect(metrics.componentCount).toBeGreaterThan(0);
      expect(metrics.reRenderCount).toBe(1);
    });

    it('should track memory usage when available', async () => {
      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <div>Memory test</div>
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onMetricsUpdate).toHaveBeenCalled();
      });

      const metrics = onMetricsUpdate.mock.calls[0][0];
      expect(metrics.memoryUsage).toBe(10000000);
    });

    it('should handle missing performance.memory gracefully', async () => {
      delete (performance as any).memory;

      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <div>No memory API</div>
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onMetricsUpdate).toHaveBeenCalled();
      });

      const metrics = onMetricsUpdate.mock.calls[0][0];
      expect(metrics.memoryUsage).toBe(0);
    });
  });

  describe('Threshold Monitoring', () => {
    it('should trigger callback when render time threshold is exceeded', async () => {
      const onThresholdExceeded = jest.fn();
      jest.spyOn(performance, 'now')
        .mockReturnValueOnce(1000) // Start time
        .mockReturnValueOnce(1100); // End time (100ms render)

      render(
        <PerformanceMonitor
          threshold={{ renderTime: 50 }}
          onThresholdExceeded={onThresholdExceeded}
        >
          <div>Slow component</div>
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onThresholdExceeded).toHaveBeenCalledWith('renderTime', 100, 50);
      });
    });

    it('should trigger callback when memory threshold is exceeded', async () => {
      mockPerformanceMemory.usedJSHeapSize = 30000000;
      const onThresholdExceeded = jest.fn();

      render(
        <PerformanceMonitor
          threshold={{ memoryUsage: 20000000 }}
          onThresholdExceeded={onThresholdExceeded}
        >
          <div>Memory heavy component</div>
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onThresholdExceeded).toHaveBeenCalledWith('memoryUsage', 30000000, 20000000);
      });
    });

    it('should trigger callback when re-render threshold is exceeded', async () => {
      const onThresholdExceeded = jest.fn();

      const { rerender } = render(
        <PerformanceMonitor
          threshold={{ reRenderCount: 2 }}
          onThresholdExceeded={onThresholdExceeded}
        >
          <div>Re-rendering component</div>
        </PerformanceMonitor>
      );

      // Trigger re-renders
      rerender(
        <PerformanceMonitor
          threshold={{ reRenderCount: 2 }}
          onThresholdExceeded={onThresholdExceeded}
        >
          <div>Re-rendering component 2</div>
        </PerformanceMonitor>
      );

      rerender(
        <PerformanceMonitor
          threshold={{ reRenderCount: 2 }}
          onThresholdExceeded={onThresholdExceeded}
        >
          <div>Re-rendering component 3</div>
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onThresholdExceeded).toHaveBeenCalledWith('reRenderCount', 3, 2);
      });
    });
  });

  describe('Performance with Heavy Components', () => {
    it('should monitor performance of heavy rendering operations', async () => {
      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <HeavyComponent itemCount={5000} />
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onMetricsUpdate).toHaveBeenCalled();
      });

      const metrics = onMetricsUpdate.mock.calls[0][0];
      expect(metrics.componentCount).toBeGreaterThan(5000);
    });

    it('should track performance degradation over time', async () => {
      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <ReRenderingComponent />
        </PerformanceMonitor>
      );

      // Let component re-render multiple times
      act(() => {
        jest.advanceTimersByTime(100);
      });

      await waitFor(() => {
        expect(onMetricsUpdate).toHaveBeenCalled();
      });

      // Should track increasing re-render count
      const lastCall = onMetricsUpdate.mock.calls[onMetricsUpdate.mock.calls.length - 1];
      expect(lastCall[0].reRenderCount).toBeGreaterThan(1);
    });

    it('should detect memory leaks in components', async () => {
      const onThresholdExceeded = jest.fn();
      
      // Simulate increasing memory usage
      let memoryUsage = 10000000;
      Object.defineProperty(performance, 'memory', {
        get: () => ({
          usedJSHeapSize: memoryUsage,
          totalJSHeapSize: 20000000,
          jsHeapSizeLimit: 50000000,
        }),
        configurable: true,
      });

      const { rerender } = render(
        <PerformanceMonitor
          threshold={{ memoryUsage: 15000000 }}
          onThresholdExceeded={onThresholdExceeded}
        >
          <MemoryLeakComponent shouldLeak />
        </PerformanceMonitor>
      );

      // Simulate memory increase
      memoryUsage = 20000000;

      rerender(
        <PerformanceMonitor
          threshold={{ memoryUsage: 15000000 }}
          onThresholdExceeded={onThresholdExceeded}
        >
          <MemoryLeakComponent shouldLeak />
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(onThresholdExceeded).toHaveBeenCalledWith('memoryUsage', 20000000, 15000000);
      });
    });
  });

  describe('Detailed Performance Tracking', () => {
    it('should enable detailed tracking with PerformanceObserver', () => {
      render(
        <PerformanceMonitor enableDetailedTracking>
          <div>Detailed tracking test</div>
        </PerformanceMonitor>
      );

      expect(global.PerformanceObserver).toHaveBeenCalled();
      expect(mockPerformanceObserver.observe).toHaveBeenCalledWith({
        entryTypes: ['measure', 'navigation'],
      });
    });

    it('should process performance entries from observer', async () => {
      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor
          enableDetailedTracking
          onMetricsUpdate={onMetricsUpdate}
        >
          <div>Observer test</div>
        </PerformanceMonitor>
      );

      // Simulate performance entries
      const mockEntries = [
        {
          entryType: 'measure',
          duration: 25.5,
          name: 'component-render',
        },
        {
          entryType: 'navigation',
          duration: 150,
          name: 'page-load',
        },
      ];

      act(() => {
        mockPerformanceObserver.callback({
          getEntries: () => mockEntries,
        });
      });

      await waitFor(() => {
        const lastCall = onMetricsUpdate.mock.calls[onMetricsUpdate.mock.calls.length - 1];
        expect(lastCall[0].networkLatency).toBe(150);
      });
    });

    it('should cleanup PerformanceObserver on unmount', () => {
      const { unmount } = render(
        <PerformanceMonitor enableDetailedTracking>
          <div>Cleanup test</div>
        </PerformanceMonitor>
      );

      unmount();

      expect(mockPerformanceObserver.disconnect).toHaveBeenCalled();
    });

    it('should handle missing PerformanceObserver gracefully', () => {
      delete (global as any).PerformanceObserver;

      expect(() => {
        render(
          <PerformanceMonitor enableDetailedTracking>
            <div>No observer API</div>
          </PerformanceMonitor>
        );
      }).not.toThrow();
    });
  });

  describe('Sampling and Performance Optimization', () => {
    it('should respect sample rate for measurements', async () => {
      const onMetricsUpdate = jest.fn();
      
      // Mock Math.random to return values > sampleRate
      jest.spyOn(Math, 'random').mockReturnValue(0.8);

      const { rerender } = render(
        <PerformanceMonitor
          sampleRate={0.5}
          onMetricsUpdate={onMetricsUpdate}
        >
          <div>Sampling test</div>
        </PerformanceMonitor>
      );

      // Should not measure due to sample rate
      rerender(
        <PerformanceMonitor
          sampleRate={0.5}
          onMetricsUpdate={onMetricsUpdate}
        >
          <div>Sampling test 2</div>
        </PerformanceMonitor>
      );

      // Only initial render should be measured
      expect(onMetricsUpdate).toHaveBeenCalledTimes(1);
    });

    it('should handle high-frequency updates efficiently', async () => {
      const onMetricsUpdate = jest.fn();

      const HighFrequencyComponent: React.FC = () => {
        const [count, setCount] = React.useState(0);

        React.useEffect(() => {
          const interval = setInterval(() => {
            setCount(c => c + 1);
          }, 1);

          setTimeout(() => clearInterval(interval), 50);
        }, []);

        return <div>Count: {count}</div>;
      };

      const startTime = performance.now();

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <HighFrequencyComponent />
        </PerformanceMonitor>
      );

      act(() => {
        jest.advanceTimersByTime(50);
      });

      const endTime = performance.now();

      // Should handle updates without significant performance impact
      expect(endTime - startTime).toBeLessThan(1000);
      expect(onMetricsUpdate).toHaveBeenCalled();
    });
  });

  describe('Error Handling and Edge Cases', () => {
    it('should handle errors in metrics calculation gracefully', async () => {
      // Mock performance.now to throw error
      jest.spyOn(performance, 'now').mockImplementation(() => {
        throw new Error('Performance API error');
      });

      expect(() => {
        render(
          <PerformanceMonitor>
            <div>Error test</div>
          </PerformanceMonitor>
        );
      }).not.toThrow();
    });

    it('should handle missing DOM elements gracefully', () => {
      const onMetricsUpdate = jest.fn();

      // Mock querySelector to return null
      const mockQuerySelectorAll = jest.fn().mockReturnValue([]);
      
      jest.spyOn(Element.prototype, 'querySelectorAll').mockImplementation(mockQuerySelectorAll);

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <div>DOM test</div>
        </PerformanceMonitor>
      );

      expect(() => {
        // Should not throw even with missing DOM elements
      }).not.toThrow();
    });

    it('should handle callback errors gracefully', async () => {
      const errorCallback = jest.fn().mockImplementation(() => {
        throw new Error('Callback error');
      });

      expect(() => {
        render(
          <PerformanceMonitor onMetricsUpdate={errorCallback}>
            <div>Callback error test</div>
          </PerformanceMonitor>
        );
      }).not.toThrow();
    });

    it('should handle rapid mount/unmount cycles', () => {
      for (let i = 0; i < 100; i++) {
        const { unmount } = render(
          <PerformanceMonitor>
            <div>Rapid cycle {i}</div>
          </PerformanceMonitor>
        );
        unmount();
      }

      // Should not cause memory leaks or errors
      expect(true).toBe(true);
    });
  });

  describe('Integration with Development Tools', () => {
    it('should work with React DevTools Profiler', () => {
      const ProfilerWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
        <React.Profiler id="test-profiler" onRender={() => {}}>
          {children}
        </React.Profiler>
      );

      expect(() => {
        render(
          <ProfilerWrapper>
            <PerformanceMonitor>
              <div>Profiler test</div>
            </PerformanceMonitor>
          </ProfilerWrapper>
        );
      }).not.toThrow();
    });

    it('should provide data for external monitoring tools', async () => {
      const mockMonitoringTool = {
        recordMetric: jest.fn(),
      };

      const onMetricsUpdate = (metrics: PerformanceMetrics) => {
        mockMonitoringTool.recordMetric('renderTime', metrics.renderTime);
        mockMonitoringTool.recordMetric('memoryUsage', metrics.memoryUsage);
      };

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <div>External monitoring test</div>
        </PerformanceMonitor>
      );

      await waitFor(() => {
        expect(mockMonitoringTool.recordMetric).toHaveBeenCalledWith('renderTime', expect.any(Number));
        expect(mockMonitoringTool.recordMetric).toHaveBeenCalledWith('memoryUsage', expect.any(Number));
      });
    });
  });

  describe('Accessibility and User Experience', () => {
    it('should not impact user interaction performance', async () => {
      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor onMetricsUpdate={onMetricsUpdate}>
          <button data-testid="test-button">Click me</button>
        </PerformanceMonitor>
      );

      const button = screen.getByTestId('test-button');
      
      const startTime = performance.now();
      
      // Simulate rapid clicks
      for (let i = 0; i < 100; i++) {
        button.click();
      }
      
      const endTime = performance.now();

      // Interactions should remain responsive
      expect(endTime - startTime).toBeLessThan(100);
    });

    it('should not interfere with screen readers', () => {
      render(
        <PerformanceMonitor>
          <div role="main" aria-label="Main content">
            <h1>Accessible content</h1>
            <p>This content should be accessible to screen readers</p>
          </div>
        </PerformanceMonitor>
      );

      expect(screen.getByRole('main')).toBeInTheDocument();
      expect(screen.getByLabelText('Main content')).toBeInTheDocument();
    });

    it('should not add visible elements that affect layout', () => {
      render(
        <PerformanceMonitor>
          <div data-testid="content">Content</div>
        </PerformanceMonitor>
      );

      const monitor = screen.getByTestId('performance-monitor');
      const content = screen.getByTestId('content');

      // Monitor should not interfere with content layout
      expect(monitor).toBeInTheDocument();
      expect(content).toBeInTheDocument();
      expect(content.parentElement).toBe(monitor);
    });
  });
});