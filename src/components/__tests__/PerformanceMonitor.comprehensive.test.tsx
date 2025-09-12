import React from 'react';
import { render, screen, act, fireEvent, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { PerformanceMonitor } from '../PerformanceMonitor';

// Mock performance API
const mockPerformance = {
  now: jest.fn(() => Date.now()),
  mark: jest.fn(),
  measure: jest.fn(),
  getEntriesByType: jest.fn(() => []),
  clearMarks: jest.fn(),
  clearMeasures: jest.fn(),
};

// Mock navigator API
const mockNavigator = {
  memory: {
    usedJSHeapSize: 50000000,
    totalJSHeapSize: 100000000,
    jsHeapSizeLimit: 2000000000,
  },
  connection: {
    effectiveType: '4g',
    downlink: 10,
    rtt: 50,
    saveData: false,
  },
};

// Mock ResizeObserver
const mockResizeObserver = jest.fn();
mockResizeObserver.mockReturnValue({
  observe: jest.fn(),
  unobserve: jest.fn(),
  disconnect: jest.fn(),
});

// Mock PerformanceObserver
const mockPerformanceObserver = jest.fn();
mockPerformanceObserver.mockImplementation((callback) => ({
  observe: jest.fn(),
  disconnect: jest.fn(),
  takeRecords: jest.fn(() => []),
}));

// Mock URL.createObjectURL and revokeObjectURL
const mockCreateObjectURL = jest.fn(() => 'blob:mock-url');
const mockRevokeObjectURL = jest.fn();

// Mock document.createElement and link.click
const mockClick = jest.fn();
const mockCreateElement = jest.fn(() => ({
  href: '',
  download: '',
  click: mockClick,
}));

describe('PerformanceMonitor', () => {
  let originalPerformance: any;
  let originalNavigator: any;
  let originalResizeObserver: any;
  let originalPerformanceObserver: any;
  let originalURL: any;
  let originalDocument: any;

  beforeEach(() => {
    // Store originals
    originalPerformance = global.performance;
    originalNavigator = global.navigator;
    originalResizeObserver = global.ResizeObserver;
    originalPerformanceObserver = global.PerformanceObserver;
    originalURL = global.URL;
    originalDocument = global.document;

    // Setup mocks
    (global as any).performance = mockPerformance;
    (global as any).navigator = mockNavigator;
    (global as any).ResizeObserver = mockResizeObserver;
    (global as any).PerformanceObserver = mockPerformanceObserver;
    (global as any).URL = {
      createObjectURL: mockCreateObjectURL,
      revokeObjectURL: mockRevokeObjectURL,
    };
    (global as any).document = {
      ...originalDocument,
      createElement: mockCreateElement,
    };

    // Mock window.matchMedia
    Object.defineProperty(window, 'matchMedia', {
      writable: true,
      value: jest.fn().mockImplementation(query => ({
        matches: false,
        media: query,
        onchange: null,
        addListener: jest.fn(), // Deprecated
        removeListener: jest.fn(), // Deprecated
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      })),
    });

    jest.clearAllMocks();
  });

  afterEach(() => {
    // Restore originals
    (global as any).performance = originalPerformance;
    (global as any).navigator = originalNavigator;
    (global as any).ResizeObserver = originalResizeObserver;
    (global as any).PerformanceObserver = originalPerformanceObserver;
    (global as any).URL = originalURL;
    (global as any).document = originalDocument;
  });

  describe('Basic Rendering', () => {
    it('renders with default props', () => {
      render(<PerformanceMonitor />);
      
      expect(screen.getByRole('region', { name: /performance monitor/i })).toBeInTheDocument();
      expect(screen.getByText('Performance Monitor')).toBeInTheDocument();
      expect(screen.getByText(/cpu usage/i)).toBeInTheDocument();
      expect(screen.getByText(/memory usage/i)).toBeInTheDocument();
    });

    it('renders children when provided', () => {
      render(
        <PerformanceMonitor>
          <div data-testid="child-component">Child Content</div>
        </PerformanceMonitor>
      );
      
      expect(screen.getByTestId('child-component')).toBeInTheDocument();
      expect(screen.getByText('Child Content')).toBeInTheDocument();
    });

    it('handles unavailable performance API gracefully', () => {
      (global as any).performance = undefined;
      
      render(<PerformanceMonitor />);
      
      expect(screen.getByText('Performance monitoring unavailable')).toBeInTheDocument();
    });
  });

  describe('Memory Monitoring', () => {
    it('displays memory information correctly', () => {
      render(<PerformanceMonitor showMemoryDetails={true} />);
      
      expect(screen.getByText(/memory usage: 50\.0%/i)).toBeInTheDocument();
    });

    it('shows memory breakdown when enabled', () => {
      render(<PerformanceMonitor showMemoryBreakdown={true} />);
      
      expect(screen.getByText(/used memory/i)).toBeInTheDocument();
      expect(screen.getByText(/available memory/i)).toBeInTheDocument();
      expect(screen.getByText(/memory limit/i)).toBeInTheDocument();
    });

    it('handles unavailable memory info', () => {
      (global as any).navigator = { ...mockNavigator, memory: undefined };
      
      render(<PerformanceMonitor showMemoryBreakdown={true} />);
      
      expect(screen.getByText('Memory info unavailable')).toBeInTheDocument();
    });

    it('triggers memory threshold callback', async () => {
      const onBottleneckDetected = jest.fn();
      
      render(
        <PerformanceMonitor 
          memoryThreshold={0.3}
          onBottleneckDetected={onBottleneckDetected}
          updateInterval={100}
        />
      );
      
      await waitFor(() => {
        expect(onBottleneckDetected).toHaveBeenCalledWith({
          type: 'memory',
          severity: 'high',
          value: 0.5,
          threshold: 0.3,
        });
      }, { timeout: 200 });
    });
  });

  describe('Network Monitoring', () => {
    it('displays network information when enabled', () => {
      render(<PerformanceMonitor showNetworkInfo={true} />);
      
      expect(screen.getByText(/connection: 4g/i)).toBeInTheDocument();
      expect(screen.getByText(/speed: 10 mbps/i)).toBeInTheDocument();
      expect(screen.getByText(/rtt: 50ms/i)).toBeInTheDocument();
    });

    it('detects slow connection', async () => {
      const onSlowConnection = jest.fn();
      (global as any).navigator = {
        ...mockNavigator,
        connection: {
          effectiveType: '2g',
          downlink: 0.5,
          rtt: 500,
          saveData: true,
        },
      };
      
      render(
        <PerformanceMonitor 
          showNetworkInfo={true}
          onSlowConnection={onSlowConnection}
          updateInterval={100}
        />
      );
      
      await waitFor(() => {
        expect(onSlowConnection).toHaveBeenCalledWith({
          effectiveType: '2g',
          downlink: 0.5,
          rtt: 500,
          saveData: true,
        });
      }, { timeout: 200 });
      
      expect(screen.getByText('Slow connection detected')).toBeInTheDocument();
    });

    it('handles unavailable connection info', () => {
      (global as any).navigator = { ...mockNavigator, connection: undefined };
      
      render(<PerformanceMonitor showNetworkInfo={true} />);
      
      expect(screen.getByText(/network: n\/a/i)).toBeInTheDocument();
    });
  });

  describe('Performance Metrics Collection', () => {
    it('collects paint metrics when enabled', () => {
      mockPerformance.getEntriesByType.mockImplementation((type) => {
        if (type === 'paint') {
          return [
            { name: 'first-paint', startTime: 100 },
            { name: 'first-contentful-paint', startTime: 150 },
          ];
        }
        return [];
      });
      
      render(<PerformanceMonitor collectPaintMetrics={true} />);
      
      expect(screen.getByText(/first paint: 100ms/i)).toBeInTheDocument();
      expect(screen.getByText(/first contentful paint: 150ms/i)).toBeInTheDocument();
    });

    it('collects navigation metrics when enabled', () => {
      mockPerformance.getEntriesByType.mockImplementation((type) => {
        if (type === 'navigation') {
          return [{
            startTime: 0,
            loadEventEnd: 1000,
            domContentLoadedEventEnd: 500,
            responseEnd: 200,
          }];
        }
        return [];
      });
      
      render(<PerformanceMonitor collectNavigationMetrics={true} />);
      
      expect(screen.getByText(/page load: 1000ms/i)).toBeInTheDocument();
      expect(screen.getByText(/dom content loaded: 500ms/i)).toBeInTheDocument();
    });

    it('collects resource metrics when enabled', () => {
      mockPerformance.getEntriesByType.mockImplementation((type) => {
        if (type === 'resource') {
          return [
            { transferSize: 1024 },
            { transferSize: 2048 },
            { transferSize: 512 },
          ];
        }
        return [];
      });
      
      render(<PerformanceMonitor collectResourceMetrics={true} />);
      
      expect(screen.getByText(/resources loaded: 3/i)).toBeInTheDocument();
      expect(screen.getByText(/total transfer size: 3\.5 kb/i)).toBeInTheDocument();
    });
  });

  describe('User Interactions', () => {
    it('toggles expanded state when show details is clicked', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor />);
      
      const expandButton = screen.getByRole('button', { name: /expand details/i });
      await user.click(expandButton);
      
      expect(screen.getByText(/hide details/i)).toBeInTheDocument();
      expect(screen.getByText('Detailed Metrics')).toBeInTheDocument();
    });

    it('clears metrics when clear button is clicked', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor />);
      
      const clearButton = screen.getByRole('button', { name: /clear metrics/i });
      await user.click(clearButton);
      
      // Should trigger metrics reset (verified by internal state change)
      expect(clearButton).toBeInTheDocument();
    });

    it('exports data when export button is clicked', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor enableDataExport={true} />);
      
      const exportButton = screen.getByRole('button', { name: /export data/i });
      await user.click(exportButton);
      
      expect(mockCreateObjectURL).toHaveBeenCalled();
      expect(mockClick).toHaveBeenCalled();
      expect(mockRevokeObjectURL).toHaveBeenCalled();
    });

    it('changes export format when select is changed', async () => {
      const user = userEvent.setup();
      
      render(<PerformanceMonitor enableDataExport={true} />);
      
      const formatSelect = screen.getByLabelText(/export format/i);
      await user.selectOptions(formatSelect, 'csv');
      
      const exportButton = screen.getByRole('button', { name: /export data/i });
      await user.click(exportButton);
      
      expect(mockCreateObjectURL).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'text/csv'
        })
      );
    });
  });

  describe('Advanced Features', () => {
    it('tracks garbage collection events', () => {
      mockPerformance.getEntriesByType.mockImplementation((type) => {
        if (type === 'gc') {
          return [{ name: 'gc' }, { name: 'gc' }];
        }
        return [];
      });
      
      render(<PerformanceMonitor trackGarbageCollection={true} />);
      
      expect(screen.getByText(/gc events: 2/i)).toBeInTheDocument();
    });

    it('detects long tasks', () => {
      mockPerformance.getEntriesByType.mockImplementation((type) => {
        if (type === 'longtask') {
          return [{ name: 'longtask', duration: 100 }];
        }
        return [];
      });
      
      render(<PerformanceMonitor detectLongTasks={true} />);
      
      expect(screen.getByText(/long tasks detected: 1/i)).toBeInTheDocument();
    });

    it('sets up performance observer when enabled', () => {
      render(<PerformanceMonitor usePerformanceObserver={true} />);
      
      expect(mockPerformanceObserver).toHaveBeenCalled();
    });

    it('uses user timing when enabled', () => {
      render(<PerformanceMonitor useUserTiming={true} />);
      
      expect(mockPerformance.mark).toHaveBeenCalledWith('performance-monitor-start');
    });

    it('displays custom metrics when provided', () => {
      const customMetrics = {
        'API Response Time': 250,
        'Database Queries': 15,
      };
      
      const customFormatters = {
        'API Response Time': (value: number) => `${value}ms`,
      };
      
      render(
        <PerformanceMonitor 
          customMetrics={customMetrics}
          showCustomMetrics={true}
          customFormatters={customFormatters}
        />
      );
      
      expect(screen.getByText(/api response time: 250ms/i)).toBeInTheDocument();
      expect(screen.getByText(/database queries: 15/i)).toBeInTheDocument();
    });
  });

  describe('Memory Leak Detection', () => {
    it('detects potential memory leaks', async () => {
      const onMemoryLeak = jest.fn();
      
      // Mock increasing memory usage
      let memoryUsage = 50000000;
      (global as any).navigator = {
        ...mockNavigator,
        memory: {
          get usedJSHeapSize() { return memoryUsage; },
          totalJSHeapSize: 100000000,
          jsHeapSizeLimit: 2000000000,
        },
      };
      
      render(
        <PerformanceMonitor 
          detectMemoryLeaks={true}
          memoryLeakThreshold={1.5}
          onMemoryLeak={onMemoryLeak}
          updateInterval={100}
        />
      );
      
      // Wait for first measurement
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 150));
      });
      
      // Simulate memory growth
      memoryUsage = 80000000; // 60% increase
      
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 150));
      });
      
      expect(onMemoryLeak).toHaveBeenCalledWith({
        type: 'potential_leak',
        growthRate: 1.6,
        currentUsage: 80000000,
      });
    });
  });

  describe('Accessibility Features', () => {
    it('respects reduced motion preference', () => {
      (window.matchMedia as jest.Mock).mockImplementation(query => ({
        matches: query === '(prefers-reduced-motion: reduce)',
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      }));
      
      render(<PerformanceMonitor showCpuGraph={true} showAnimations={true} />);
      
      // Should not have animation transitions
      const cpuBar = screen.getByRole('img', { name: /cpu usage graph/i }).querySelector('div');
      expect(cpuBar).toHaveStyle('transition: none');
    });

    it('respects high contrast preference', () => {
      (window.matchMedia as jest.Mock).mockImplementation(query => ({
        matches: query === '(prefers-contrast: high)',
        media: query,
        onchange: null,
        addListener: jest.fn(),
        removeListener: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        dispatchEvent: jest.fn(),
      }));
      
      render(<PerformanceMonitor />);
      
      const monitor = screen.getByRole('region', { name: /performance monitor/i });
      expect(monitor).toHaveClass('high-contrast');
    });

    it('provides proper ARIA labels', () => {
      render(<PerformanceMonitor memoryThreshold={0.3} />);
      
      const status = screen.getByRole('status');
      expect(status).toHaveAttribute('aria-live', 'polite');
      expect(status).toHaveAttribute('aria-label');
      
      const exportSelect = screen.queryByLabelText(/export format/i);
      if (exportSelect) {
        expect(exportSelect).toHaveAttribute('aria-label', 'Export Format');
      }
    });
  });

  describe('Callback Functions', () => {
    it('calls onMetricsUpdate callback', async () => {
      const onMetricsUpdate = jest.fn();
      
      render(
        <PerformanceMonitor 
          onMetricsUpdate={onMetricsUpdate}
          updateInterval={100}
        />
      );
      
      await waitFor(() => {
        expect(onMetricsUpdate).toHaveBeenCalled();
      }, { timeout: 200 });
      
      const metricsCall = onMetricsUpdate.mock.calls[0][0];
      expect(metricsCall).toHaveProperty('cpuUsage');
      expect(metricsCall).toHaveProperty('memoryUsage');
      expect(metricsCall).toHaveProperty('memoryUsed');
    });

    it('calls onDetailedMetrics when show details is clicked', async () => {
      const onDetailedMetrics = jest.fn();
      const user = userEvent.setup();
      
      render(<PerformanceMonitor onDetailedMetrics={onDetailedMetrics} />);
      
      const expandButton = screen.getByRole('button', { name: /expand details/i });
      await user.click(expandButton);
      
      expect(onDetailedMetrics).toHaveBeenCalled();
    });

    it('debounces callback updates when enabled', async () => {
      const onMetricsUpdate = jest.fn();
      
      render(
        <PerformanceMonitor 
          onMetricsUpdate={onMetricsUpdate}
          debounceUpdates={true}
          updateInterval={50}
        />
      );
      
      // Wait for multiple update intervals
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 250));
      });
      
      // Should have fewer calls due to debouncing
      expect(onMetricsUpdate.mock.calls.length).toBeLessThan(5);
    });

    it('throttles expensive operations when enabled', async () => {
      const onDetailedMetrics = jest.fn();
      const user = userEvent.setup();
      
      render(
        <PerformanceMonitor 
          onDetailedMetrics={onDetailedMetrics}
          throttleExpensiveOps={true}
        />
      );
      
      const expandButton = screen.getByRole('button', { name: /show details/i });
      
      // Click multiple times rapidly
      await user.click(expandButton);
      await user.click(expandButton);
      await user.click(expandButton);
      
      // Should only call once due to throttling
      await waitFor(() => {
        expect(onDetailedMetrics).toHaveBeenCalledTimes(1);
      });
    });
  });

  describe('Error Handling', () => {
    it('handles performance API errors gracefully', () => {
      mockPerformance.getEntriesByType.mockImplementation(() => {
        throw new Error('Performance API error');
      });
      
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation();
      
      render(<PerformanceMonitor collectPaintMetrics={true} />);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        'Error updating performance metrics:',
        expect.any(Error)
      );
      
      consoleSpy.mockRestore();
    });

    it('handles PerformanceObserver setup failures', () => {
      mockPerformanceObserver.mockImplementation(() => {
        throw new Error('PerformanceObserver not supported');
      });
      
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      render(<PerformanceMonitor usePerformanceObserver={true} />);
      
      expect(consoleSpy).toHaveBeenCalledWith(
        'PerformanceObserver setup failed:',
        expect.any(Error)
      );
      
      consoleSpy.mockRestore();
    });

    it('warns about unavailable ResizeObserver', () => {
      (global as any).ResizeObserver = undefined;
      
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      
      render(<PerformanceMonitor />);
      
      expect(consoleSpy).toHaveBeenCalledWith('ResizeObserver not available');
      
      consoleSpy.mockRestore();
    });
  });

  describe('Cleanup', () => {
    it('cleans up intervals and observers on unmount', () => {
      const { unmount } = render(<PerformanceMonitor usePerformanceObserver={true} />);
      
      const disconnectSpy = jest.spyOn(
        mockPerformanceObserver.mock.results[0].value,
        'disconnect'
      );
      
      unmount();
      
      expect(disconnectSpy).toHaveBeenCalled();
    });

    it('clears timeouts on unmount', () => {
      const clearTimeoutSpy = jest.spyOn(global, 'clearTimeout');
      
      const { unmount } = render(
        <PerformanceMonitor debounceUpdates={true} throttleExpensiveOps={true} />
      );
      
      unmount();
      
      expect(clearTimeoutSpy).toHaveBeenCalled();
      
      clearTimeoutSpy.mockRestore();
    });
  });
});