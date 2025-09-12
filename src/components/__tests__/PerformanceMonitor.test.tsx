/**
 * Performance Monitor Component Tests
 * Tests performance tracking, memory monitoring, and accessibility
 */

import React from 'react';
import { render, screen, act, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PerformanceMonitor } from '../PerformanceMonitor';

// Mock Performance API
const mockPerformance = {
  now: jest.fn(() => Date.now()),
  mark: jest.fn(),
  measure: jest.fn(),
  getEntriesByType: jest.fn(() => []),
  getEntriesByName: jest.fn(() => []),
  observer: null
};

// Mock PerformanceObserver
const mockPerformanceObserver = jest.fn((callback) => ({
  observe: jest.fn(),
  disconnect: jest.fn(),
  takeRecords: jest.fn(() => []),
}));

// Mock memory API
Object.defineProperty(navigator, 'memory', {
  value: {
    usedJSHeapSize: 50000000,
    totalJSHeapSize: 100000000,
    jsHeapSizeLimit: 2000000000
  },
  writable: true
});

beforeAll(() => {
  global.performance = mockPerformance as any;
  global.PerformanceObserver = mockPerformanceObserver as any;
});

describe('PerformanceMonitor', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockPerformance.now.mockImplementation(() => Date.now());
  });

  describe('Basic Rendering', () => {
    it('should render performance metrics', () => {
      render(<PerformanceMonitor />);

      expect(screen.getByText(/Performance Monitor/)).toBeInTheDocument();
      expect(screen.getByText(/CPU Usage/)).toBeInTheDocument();
      expect(screen.getByText(/Memory Usage/)).toBeInTheDocument();
      expect(screen.getByText(/Network/)).toBeInTheDocument();
    });

    it('should display current memory usage', () => {
      render(<PerformanceMonitor showMemoryDetails={true} />);

      expect(screen.getByText(/47\.7 MB/)).toBeInTheDocument(); // usedJSHeapSize
      expect(screen.getByText(/95\.4 MB/)).toBeInTheDocument(); // totalJSHeapSize
    });

    it('should show performance status indicator', () => {
      render(<PerformanceMonitor />);

      const statusIndicator = screen.getByRole('status');
      expect(statusIndicator).toBeInTheDocument();
      expect(statusIndicator).toHaveAttribute('aria-label', expect.stringContaining('Performance'));
    });
  });

  describe('Real-time Monitoring', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should update metrics periodically', async () => {
      const onMetricsUpdate = jest.fn();
      
      render(
        <PerformanceMonitor 
          updateInterval={1000}
          onMetricsUpdate={onMetricsUpdate}
        />
      );

      // Fast-forward time to trigger updates
      act(() => {
        jest.advanceTimersByTime(1000);
      });

      expect(onMetricsUpdate).toHaveBeenCalled();
    });

    it('should track CPU usage over time', async () => {
      let cpuUsage = 10;
      mockPerformance.now.mockImplementation(() => {
        cpuUsage += Math.random() * 10;
        return Date.now() + cpuUsage * 1000;
      });

      render(<PerformanceMonitor showCpuGraph={true} />);

      act(() => {
        jest.advanceTimersByTime(5000);
      });

      expect(screen.getByRole('img', { name: /CPU usage graph/i })).toBeInTheDocument();
    });

    it('should detect performance bottlenecks', async () => {
      const onBottleneckDetected = jest.fn();
      
      // Mock high memory usage
      Object.defineProperty(navigator, 'memory', {
        value: {
          usedJSHeapSize: 180000000, // 90% of total
          totalJSHeapSize: 200000000,
          jsHeapSizeLimit: 2000000000
        }
      });

      render(
        <PerformanceMonitor 
          memoryThreshold={0.8}
          onBottleneckDetected={onBottleneckDetected}
        />
      );

      act(() => {
        jest.advanceTimersByTime(2000);
      });

      expect(onBottleneckDetected).toHaveBeenCalledWith({
        type: 'memory',
        severity: 'high',
        value: expect.any(Number),
        threshold: 0.8
      });
    });
  });

  describe('Performance Metrics Collection', () => {
    it('should collect paint timing metrics', () => {
      mockPerformance.getEntriesByType.mockReturnValue([
        { name: 'first-paint', startTime: 100 },
        { name: 'first-contentful-paint', startTime: 200 }
      ]);

      render(<PerformanceMonitor collectPaintMetrics={true} />);

      expect(mockPerformance.getEntriesByType).toHaveBeenCalledWith('paint');
      expect(screen.getByText(/First Paint:/)).toBeInTheDocument();
      expect(screen.getByText(/100ms/)).toBeInTheDocument();
    });

    it('should collect navigation timing', () => {
      mockPerformance.getEntriesByType.mockReturnValue([
        {
          name: 'navigation',
          startTime: 0,
          loadEventEnd: 1000,
          domContentLoadedEventEnd: 500,
          responseEnd: 300
        }
      ]);

      render(<PerformanceMonitor collectNavigationMetrics={true} />);

      expect(mockPerformance.getEntriesByType).toHaveBeenCalledWith('navigation');
      expect(screen.getByText(/Page Load:/)).toBeInTheDocument();
      expect(screen.getByText(/1000ms/)).toBeInTheDocument();
    });

    it('should track resource loading performance', () => {
      mockPerformance.getEntriesByType.mockReturnValue([
        {
          name: 'https://example.com/script.js',
          startTime: 100,
          responseEnd: 300,
          transferSize: 50000
        },
        {
          name: 'https://example.com/style.css',
          startTime: 150,
          responseEnd: 250,
          transferSize: 20000
        }
      ]);

      render(<PerformanceMonitor collectResourceMetrics={true} />);

      expect(mockPerformance.getEntriesByType).toHaveBeenCalledWith('resource');
      expect(screen.getByText(/Resources Loaded:/)).toBeInTheDocument();
      expect(screen.getByText(/2/)).toBeInTheDocument();
    });
  });

  describe('Memory Monitoring', () => {
    it('should display memory usage breakdown', () => {
      render(<PerformanceMonitor showMemoryBreakdown={true} />);

      expect(screen.getByText(/Used Memory:/)).toBeInTheDocument();
      expect(screen.getByText(/Available Memory:/)).toBeInTheDocument();
      expect(screen.getByText(/Memory Limit:/)).toBeInTheDocument();
    });

    it('should warn about memory leaks', async () => {
      const onMemoryLeak = jest.fn();
      
      // Simulate increasing memory usage
      let memoryUsage = 50000000;
      Object.defineProperty(navigator, 'memory', {
        get: () => ({
          usedJSHeapSize: memoryUsage,
          totalJSHeapSize: 100000000,
          jsHeapSizeLimit: 2000000000
        })
      });

      render(
        <PerformanceMonitor 
          detectMemoryLeaks={true}
          memoryLeakThreshold={1.5}
          onMemoryLeak={onMemoryLeak}
        />
      );

      // Simulate memory growth
      act(() => {
        memoryUsage = 80000000; // 60% increase
        jest.advanceTimersByTime(10000);
      });

      await waitFor(() => {
        expect(onMemoryLeak).toHaveBeenCalledWith({
          type: 'potential_leak',
          growthRate: expect.any(Number),
          currentUsage: 80000000
        });
      });
    });

    it('should track garbage collection events', () => {
      const gcEntries = [
        { name: 'gc', startTime: 1000, duration: 50 },
        { name: 'gc', startTime: 2000, duration: 75 }
      ];

      mockPerformance.getEntriesByType.mockReturnValue(gcEntries);

      render(<PerformanceMonitor trackGarbageCollection={true} />);

      expect(screen.getByText(/GC Events:/)).toBeInTheDocument();
      expect(screen.getByText(/2/)).toBeInTheDocument();
    });
  });

  describe('Network Performance', () => {
    it('should monitor network connection', () => {
      // Mock navigator.connection
      Object.defineProperty(navigator, 'connection', {
        value: {
          effectiveType: '4g',
          downlink: 10,
          rtt: 50,
          saveData: false
        },
        writable: true
      });

      render(<PerformanceMonitor showNetworkInfo={true} />);

      expect(screen.getByText(/Connection:/)).toBeInTheDocument();
      expect(screen.getByText(/4g/)).toBeInTheDocument();
      expect(screen.getByText(/10 Mbps/)).toBeInTheDocument();
    });

    it('should warn about slow connections', () => {
      Object.defineProperty(navigator, 'connection', {
        value: {
          effectiveType: '2g',
          downlink: 0.5,
          rtt: 2000,
          saveData: true
        }
      });

      const onSlowConnection = jest.fn();

      render(
        <PerformanceMonitor 
          showNetworkInfo={true}
          onSlowConnection={onSlowConnection}
        />
      );

      expect(onSlowConnection).toHaveBeenCalledWith({
        effectiveType: '2g',
        downlink: 0.5,
        rtt: 2000
      });

      expect(screen.getByText(/Slow connection detected/)).toBeInTheDocument();
    });
  });

  describe('User Interaction Tracking', () => {
    it('should measure user interaction latency', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor trackInteractions={true} />);

      const button = screen.getByRole('button', { name: /Clear Metrics/ });
      
      await user.click(button);

      expect(mockPerformance.mark).toHaveBeenCalledWith(
        expect.stringMatching(/interaction-start/)
      );
      expect(mockPerformance.measure).toHaveBeenCalledWith(
        expect.stringMatching(/interaction-duration/),
        expect.stringMatching(/interaction-start/)
      );
    });

    it('should track input delay', async () => {
      const user = userEvent.setup();
      
      render(
        <PerformanceMonitor trackInteractions={true}>
          <input data-testid="test-input" type="text" />
        </PerformanceMonitor>
      );

      const input = screen.getByTestId('test-input');
      
      await user.type(input, 'test');

      // Should track input delay
      expect(mockPerformance.mark).toHaveBeenCalled();
    });
  });

  describe('Accessibility', () => {
    it('should be accessible to screen readers', () => {
      render(<PerformanceMonitor />);

      expect(screen.getByRole('region', { name: /Performance Monitor/ })).toBeInTheDocument();
      expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite');
    });

    it('should provide keyboard navigation', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor />);

      const expandButton = screen.getByRole('button', { name: /Expand Details/ });
      
      await user.tab();
      expect(expandButton).toHaveFocus();

      await user.keyboard('{Enter}');
      expect(screen.getByText(/Detailed Metrics/)).toBeInTheDocument();
    });

    it('should support high contrast mode', () => {
      // Mock high contrast media query
      Object.defineProperty(window, 'matchMedia', {
        writable: true,
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('prefers-contrast: high'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      render(<PerformanceMonitor />);

      const monitor = screen.getByRole('region');
      expect(monitor).toHaveClass('high-contrast');
    });

    it('should respect reduced motion preferences', () => {
      Object.defineProperty(window, 'matchMedia', {
        value: jest.fn().mockImplementation(query => ({
          matches: query.includes('prefers-reduced-motion: reduce'),
          media: query,
          onchange: null,
          addListener: jest.fn(),
          removeListener: jest.fn(),
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          dispatchEvent: jest.fn(),
        })),
      });

      render(<PerformanceMonitor showAnimations={true} />);

      const animatedElements = screen.queryAllByClass('animate');
      expect(animatedElements).toHaveLength(0);
    });
  });

  describe('Error Handling', () => {
    it('should handle Performance API not available', () => {
      const originalPerformance = global.performance;
      delete (global as any).performance;

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      render(<PerformanceMonitor />);

      expect(consoleSpy).toHaveBeenCalledWith(
        'Performance API not available'
      );

      expect(screen.getByText(/Performance monitoring unavailable/)).toBeInTheDocument();

      global.performance = originalPerformance;
      consoleSpy.mockRestore();
    });

    it('should handle memory API not available', () => {
      const originalMemory = navigator.memory;
      delete (navigator as any).memory;

      render(<PerformanceMonitor />);

      expect(screen.getByText(/Memory info unavailable/)).toBeInTheDocument();

      Object.defineProperty(navigator, 'memory', {
        value: originalMemory,
        writable: true
      });
    });

    it('should handle PerformanceObserver errors', () => {
      mockPerformanceObserver.mockImplementation(() => {
        throw new Error('PerformanceObserver not supported');
      });

      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();

      render(<PerformanceMonitor usePerformanceObserver={true} />);

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining('PerformanceObserver'),
        expect.any(Error)
      );

      consoleSpy.mockRestore();
    });
  });

  describe('Performance Optimizations', () => {
    it('should debounce rapid updates', () => {
      jest.useFakeTimers();
      
      const onMetricsUpdate = jest.fn();

      render(
        <PerformanceMonitor 
          onMetricsUpdate={onMetricsUpdate}
          updateInterval={100}
          debounceUpdates={true}
        />
      );

      // Trigger multiple rapid updates
      act(() => {
        jest.advanceTimersByTime(50);
        jest.advanceTimersByTime(50);
        jest.advanceTimersByTime(50);
      });

      // Should only call once due to debouncing
      expect(onMetricsUpdate).toHaveBeenCalledTimes(1);

      jest.useRealTimers();
    });

    it('should throttle expensive operations', () => {
      jest.useFakeTimers();
      
      const expensiveCallback = jest.fn();

      render(
        <PerformanceMonitor 
          onDetailedMetrics={expensiveCallback}
          throttleExpensiveOps={true}
        />
      );

      // Trigger multiple calls
      const button = screen.getByRole('button', { name: /Show Details/ });
      
      act(() => {
        button.click();
        button.click();
        button.click();
      });

      // Should be throttled
      expect(expensiveCallback).toHaveBeenCalledTimes(1);

      jest.useRealTimers();
    });

    it('should cleanup resources on unmount', () => {
      const { unmount } = render(<PerformanceMonitor />);

      const mockObserver = mockPerformanceObserver.mock.results[0]?.value;
      
      unmount();

      if (mockObserver) {
        expect(mockObserver.disconnect).toHaveBeenCalled();
      }
    });
  });

  describe('Custom Metrics', () => {
    it('should support custom performance metrics', () => {
      const customMetrics = {
        'custom-metric-1': 150,
        'custom-metric-2': 300
      };

      render(
        <PerformanceMonitor 
          customMetrics={customMetrics}
          showCustomMetrics={true}
        />
      );

      expect(screen.getByText(/custom-metric-1:/)).toBeInTheDocument();
      expect(screen.getByText(/150/)).toBeInTheDocument();
      expect(screen.getByText(/custom-metric-2:/)).toBeInTheDocument();
      expect(screen.getByText(/300/)).toBeInTheDocument();
    });

    it('should allow custom metric formatters', () => {
      const customMetrics = { 'response-time': 1234 };
      const formatters = {
        'response-time': (value: number) => `${(value / 1000).toFixed(2)}s`
      };

      render(
        <PerformanceMonitor 
          customMetrics={customMetrics}
          customFormatters={formatters}
          showCustomMetrics={true}
        />
      );

      expect(screen.getByText(/1.23s/)).toBeInTheDocument();
    });
  });

  describe('Data Export', () => {
    it('should export performance data as JSON', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor enableDataExport={true} />);

      const exportButton = screen.getByRole('button', { name: /Export Data/ });
      await user.click(exportButton);

      // Mock download should have been triggered
      expect(global.URL.createObjectURL).toHaveBeenCalled();
    });

    it('should export data in CSV format', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor enableDataExport={true} />);

      const formatSelect = screen.getByRole('combobox', { name: /Export Format/ });
      await user.selectOptions(formatSelect, 'csv');

      const exportButton = screen.getByRole('button', { name: /Export Data/ });
      await user.click(exportButton);

      expect(global.URL.createObjectURL).toHaveBeenCalled();
    });
  });

  describe('Integration with Performance APIs', () => {
    it('should integrate with User Timing API', () => {
      render(<PerformanceMonitor useUserTiming={true} />);

      expect(mockPerformance.mark).toHaveBeenCalledWith('performance-monitor-start');
      expect(mockPerformance.getEntriesByType).toHaveBeenCalledWith('measure');
    });

    it('should use Long Tasks API when available', () => {
      const longTasks = [
        { name: 'long-task', startTime: 1000, duration: 100 }
      ];

      mockPerformance.getEntriesByType.mockReturnValue(longTasks);

      render(<PerformanceMonitor detectLongTasks={true} />);

      expect(mockPerformance.getEntriesByType).toHaveBeenCalledWith('longtask');
      expect(screen.getByText(/Long Tasks Detected:/)).toBeInTheDocument();
    });
  });
});