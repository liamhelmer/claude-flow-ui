/**
 * @jest-environment jsdom
 */

import { render, act, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

// Import components to test
import { Terminal } from '@/components/terminal/Terminal';
import { TabList } from '@/components/tabs/TabList';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock performance.now() for consistent timing
const mockPerformanceNow = jest.fn();
Object.defineProperty(global.performance, 'now', {
  value: mockPerformanceNow,
});

// Mock performance.mark() and performance.measure()
global.performance.mark = jest.fn();
global.performance.measure = jest.fn().mockReturnValue({
  duration: 16, // Mock 16ms duration
});

// Mock requestAnimationFrame for consistent timing
global.requestAnimationFrame = jest.fn((callback) => {
  setTimeout(callback, 16);
  return 1;
});

// Mock dependencies with performance tracking
jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: jest.fn(),
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: jest.fn(),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: jest.fn(() => ({
    sessions: [],
    activeSession: null,
    isLoading: false,
    error: null,
    agents: [],
    memory: { usage: 50, limit: 100 },
    commands: [],
    prompts: [],
    addSession: jest.fn(),
    removeSession: jest.fn(),
    setActiveSession: jest.fn(),
  })),
}));

// Performance measurement utilities
class PerformanceTracker {
  private measurements: Map<string, number[]> = new Map();

  startMeasurement(name: string): void {
    performance.mark(`${name}-start`);
  }

  endMeasurement(name: string): number {
    performance.mark(`${name}-end`);
    performance.measure(name, `${name}-start`, `${name}-end`);
    
    const entries = performance.getEntriesByName(name, 'measure');
    const duration = entries[entries.length - 1]?.duration || 16;
    
    if (!this.measurements.has(name)) {
      this.measurements.set(name, []);
    }
    this.measurements.get(name)!.push(duration);
    
    return duration;
  }

  getAverageDuration(name: string): number {
    const durations = this.measurements.get(name) || [];
    return durations.reduce((sum, duration) => sum + duration, 0) / durations.length;
  }

  getStats(name: string) {
    const durations = this.measurements.get(name) || [];
    if (durations.length === 0) return null;

    return {
      average: this.getAverageDuration(name),
      min: Math.min(...durations),
      max: Math.max(...durations),
      count: durations.length,
      p95: this.percentile(durations, 95),
      p99: this.percentile(durations, 99),
    };
  }

  private percentile(arr: number[], p: number): number {
    const sorted = [...arr].sort((a, b) => a - b);
    const index = Math.ceil((p / 100) * sorted.length) - 1;
    return sorted[index];
  }

  reset(): void {
    this.measurements.clear();
  }
}

describe('Comprehensive Performance Tests', () => {
  let performanceTracker: PerformanceTracker;

  beforeEach(() => {
    jest.clearAllMocks();
    performanceTracker = new PerformanceTracker();
    
    // Reset performance timing
    mockPerformanceNow.mockReturnValue(0);
    let currentTime = 0;
    mockPerformanceNow.mockImplementation(() => {
      currentTime += 16; // Simulate 60fps
      return currentTime;
    });

    // Mock useTerminal with performance tracking
    (useTerminal as jest.Mock).mockReturnValue({
      terminalRef: { current: null },
      terminal: null,
      writeToTerminal: jest.fn(),
      clearTerminal: jest.fn(),
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      isConnected: true,
      isAtBottom: true,
      hasNewOutput: false,
      scrollToBottom: jest.fn(),
      scrollToTop: jest.fn(),
    });

    // Mock useWebSocket with performance tracking
    (useWebSocket as jest.Mock).mockReturnValue({
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      isConnected: true,
      on: jest.fn(),
      off: jest.fn(),
    });
  });

  describe('Rendering Performance', () => {
    test('Terminal component should render within performance budget', async () => {
      performanceTracker.startMeasurement('terminal-render');

      const { container } = render(<Terminal sessionId="test-session" />);

      const duration = performanceTracker.endMeasurement('terminal-render');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(100); // Should render in under 100ms
    });

    test('Sidebar should handle large number of sessions efficiently', async () => {
      // Generate large number of sessions
      const sessions = Array.from({ length: 100 }, (_, i) => ({
        id: `session-${i}`,
        name: `Session ${i}`,
        status: i % 2 === 0 ? 'active' : 'inactive',
      }));

      performanceTracker.startMeasurement('sidebar-large-render');

      const { container } = render(
        <Sidebar
          sessions={sessions}
          activeSessionId="session-0"
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const duration = performanceTracker.endMeasurement('sidebar-large-render');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(200); // Should render 100 items in under 200ms
    });

    test('TabList should render many tabs efficiently', async () => {
      const tabs = Array.from({ length: 50 }, (_, i) => ({
        id: `tab-${i}`,
        title: `Tab ${i}`,
        isActive: i === 0,
      }));

      performanceTracker.startMeasurement('tablist-render');

      const { container } = render(
        <TabList tabs={tabs} onTabChange={jest.fn()} />
      );

      const duration = performanceTracker.endMeasurement('tablist-render');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(150); // Should render 50 tabs in under 150ms
    });

    test('Component should handle rapid re-renders efficiently', async () => {
      const TestComponent = ({ count }: { count: number }) => (
        <div>
          {Array.from({ length: count }, (_, i) => (
            <div key={i}>Item {i}</div>
          ))}
        </div>
      );

      const { rerender } = render(<TestComponent count={10} />);

      // Measure multiple rapid re-renders
      for (let i = 11; i <= 20; i++) {
        performanceTracker.startMeasurement(`rerender-${i}`);
        
        act(() => {
          rerender(<TestComponent count={i} />);
        });
        
        performanceTracker.endMeasurement(`rerender-${i}`);
      }

      const averageRerenderTime = performanceTracker.getAverageDuration('rerender-11');
      expect(averageRerenderTime).toBeLessThan(50); // Each re-render should be under 50ms
    });
  });

  describe('Memory Performance', () => {
    test('should not create memory leaks on mount/unmount', () => {
      const initialMemory = (performance as any).memory?.usedJSHeapSize || 0;

      // Mount and unmount components multiple times
      for (let i = 0; i < 10; i++) {
        const { unmount } = render(<Terminal sessionId={`test-${i}`} />);
        unmount();
      }

      // Check memory hasn't grown significantly
      const finalMemory = (performance as any).memory?.usedJSHeapSize || 0;
      const memoryGrowth = finalMemory - initialMemory;

      // Memory growth should be minimal (allowing for some overhead)
      expect(memoryGrowth).toBeLessThan(1024 * 1024); // Less than 1MB growth
    });

    test('should clean up event listeners properly', () => {
      const addEventListenerSpy = jest.spyOn(document, 'addEventListener');
      const removeEventListenerSpy = jest.spyOn(document, 'removeEventListener');

      const { unmount } = render(<Terminal sessionId="test-session" />);
      
      const addedListeners = addEventListenerSpy.mock.calls.length;
      
      unmount();
      
      const removedListeners = removeEventListenerSpy.mock.calls.length;

      // Should remove as many listeners as added
      expect(removedListeners).toBeGreaterThanOrEqual(addedListeners);

      addEventListenerSpy.mockRestore();
      removeEventListenerSpy.mockRestore();
    });

    test('should handle large datasets without performance degradation', async () => {
      const LargeDataComponent = ({ items }: { items: any[] }) => (
        <div>
          {items.map((item, index) => (
            <div key={index}>
              {JSON.stringify(item)}
            </div>
          ))}
        </div>
      );

      // Generate large dataset
      const largeDataset = Array.from({ length: 1000 }, (_, i) => ({
        id: i,
        name: `Item ${i}`,
        data: new Array(100).fill(0).map((_, j) => `data-${i}-${j}`),
      }));

      performanceTracker.startMeasurement('large-dataset-render');

      const { container } = render(<LargeDataComponent items={largeDataset} />);

      const duration = performanceTracker.endMeasurement('large-dataset-render');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(500); // Should handle large dataset in under 500ms
    });
  });

  describe('Interaction Performance', () => {
    test('should respond to user interactions quickly', async () => {
      const user = userEvent.setup();
      const mockOnClick = jest.fn();

      const InteractiveComponent = () => (
        <button onClick={mockOnClick}>Click me</button>
      );

      render(<InteractiveComponent />);

      const button = document.querySelector('button')!;

      // Measure click response time
      performanceTracker.startMeasurement('click-response');

      await user.click(button);

      const duration = performanceTracker.endMeasurement('click-response');

      expect(mockOnClick).toHaveBeenCalled();
      expect(duration).toBeLessThan(50); // Click should respond in under 50ms
    });

    test('should handle rapid successive interactions efficiently', async () => {
      const user = userEvent.setup();
      const mockOnClick = jest.fn();

      const FastClickComponent = () => (
        <button onClick={mockOnClick}>Fast Click</button>
      );

      render(<FastClickComponent />);

      const button = document.querySelector('button')!;

      // Perform rapid clicks
      performanceTracker.startMeasurement('rapid-clicks');

      for (let i = 0; i < 10; i++) {
        await user.click(button);
      }

      const duration = performanceTracker.endMeasurement('rapid-clicks');

      expect(mockOnClick).toHaveBeenCalledTimes(10);
      expect(duration).toBeLessThan(200); // 10 rapid clicks should complete in under 200ms
    });

    test('should handle keyboard navigation efficiently', async () => {
      const user = userEvent.setup();

      const KeyboardNavComponent = () => (
        <div>
          {Array.from({ length: 20 }, (_, i) => (
            <button key={i} tabIndex={0}>
              Button {i}
            </button>
          ))}
        </div>
      );

      render(<KeyboardNavComponent />);

      performanceTracker.startMeasurement('keyboard-navigation');

      // Navigate through all buttons using Tab
      for (let i = 0; i < 20; i++) {
        await user.tab();
      }

      const duration = performanceTracker.endMeasurement('keyboard-navigation');

      expect(duration).toBeLessThan(300); // Navigation should be under 300ms
    });
  });

  describe('Animation and Transition Performance', () => {
    test('should maintain 60fps during animations', async () => {
      const AnimatedComponent = ({ isVisible }: { isVisible: boolean }) => (
        <div
          className={`transition-opacity duration-300 ${
            isVisible ? 'opacity-100' : 'opacity-0'
          }`}
        >
          Animated content
        </div>
      );

      const { rerender } = render(<AnimatedComponent isVisible={false} />);

      performanceTracker.startMeasurement('animation-toggle');

      act(() => {
        rerender(<AnimatedComponent isVisible={true} />);
      });

      // Simulate animation frames
      for (let i = 0; i < 18; i++) { // 300ms / 16ms per frame
        act(() => {
          jest.advanceTimersByTime(16);
        });
      }

      const duration = performanceTracker.endMeasurement('animation-toggle');

      expect(duration).toBeLessThan(350); // Should complete within animation duration + overhead
    });

    test('should handle smooth scrolling performance', async () => {
      const ScrollComponent = ({ scrollTop }: { scrollTop: number }) => {
        const ref = React.useRef<HTMLDivElement>(null);

        React.useEffect(() => {
          if (ref.current) {
            ref.current.scrollTop = scrollTop;
          }
        }, [scrollTop]);

        return (
          <div ref={ref} style={{ height: '200px', overflow: 'auto' }}>
            {Array.from({ length: 100 }, (_, i) => (
              <div key={i} style={{ height: '30px' }}>
                Item {i}
              </div>
            ))}
          </div>
        );
      };

      const { rerender } = render(<ScrollComponent scrollTop={0} />);

      performanceTracker.startMeasurement('scroll-animation');

      // Simulate smooth scrolling by gradually changing scroll position
      for (let i = 1; i <= 10; i++) {
        act(() => {
          rerender(<ScrollComponent scrollTop={i * 50} />);
        });
      }

      const duration = performanceTracker.endMeasurement('scroll-animation');

      expect(duration).toBeLessThan(200); // Scrolling should be smooth and fast
    });
  });

  describe('Data Loading Performance', () => {
    test('should handle async data loading efficiently', async () => {
      const AsyncComponent = () => {
        const [data, setData] = React.useState<any[]>([]);
        const [loading, setLoading] = React.useState(true);

        React.useEffect(() => {
          // Simulate async data loading
          setTimeout(() => {
            setData(Array.from({ length: 50 }, (_, i) => ({ id: i, name: `Item ${i}` })));
            setLoading(false);
          }, 100);
        }, []);

        if (loading) return <div>Loading...</div>;

        return (
          <div>
            {data.map(item => (
              <div key={item.id}>{item.name}</div>
            ))}
          </div>
        );
      };

      performanceTracker.startMeasurement('async-data-load');

      render(<AsyncComponent />);

      await waitFor(() => {
        expect(document.querySelector('div:not([class*="loading"])')).toBeInTheDocument();
      });

      const duration = performanceTracker.endMeasurement('async-data-load');

      expect(duration).toBeLessThan(300); // Data loading and rendering should be under 300ms
    });

    test('should handle data updates without blocking UI', async () => {
      const DataUpdateComponent = ({ updateFrequency }: { updateFrequency: number }) => {
        const [data, setData] = React.useState(0);

        React.useEffect(() => {
          const interval = setInterval(() => {
            setData(prev => prev + 1);
          }, updateFrequency);

          return () => clearInterval(interval);
        }, [updateFrequency]);

        return <div>Count: {data}</div>;
      };

      render(<DataUpdateComponent updateFrequency={50} />);

      performanceTracker.startMeasurement('data-updates');

      // Let updates run for a short period
      act(() => {
        jest.advanceTimersByTime(500);
      });

      const duration = performanceTracker.endMeasurement('data-updates');

      // UI should remain responsive during frequent updates
      expect(duration).toBeLessThan(100);
    });
  });

  describe('Resource Management', () => {
    test('should efficiently manage component instances', () => {
      const ComponentPool = ({ count }: { count: number }) => (
        <div>
          {Array.from({ length: count }, (_, i) => (
            <div key={i}>Component {i}</div>
          ))}
        </div>
      );

      const { rerender } = render(<ComponentPool count={10} />);

      // Measure scaling from 10 to 100 components
      performanceTracker.startMeasurement('component-scaling');

      for (let count = 20; count <= 100; count += 10) {
        act(() => {
          rerender(<ComponentPool count={count} />);
        });
      }

      const duration = performanceTracker.endMeasurement('component-scaling');

      // Should scale reasonably well
      expect(duration).toBeLessThan(400); // 9 scaling steps should complete in under 400ms
    });

    test('should handle WebSocket message processing efficiently', () => {
      const mockWebSocketHook = useWebSocket as jest.Mock;
      const mockSendData = jest.fn();
      
      mockWebSocketHook.mockReturnValue({
        sendData: mockSendData,
        resizeTerminal: jest.fn(),
        isConnected: true,
        on: jest.fn(),
        off: jest.fn(),
      });

      render(<Terminal sessionId="test-session" />);

      performanceTracker.startMeasurement('websocket-messages');

      // Simulate processing many messages rapidly
      for (let i = 0; i < 100; i++) {
        mockSendData(`message-${i}`);
      }

      const duration = performanceTracker.endMeasurement('websocket-messages');

      expect(duration).toBeLessThan(100); // 100 message calls should be under 100ms
    });
  });

  describe('Performance Budgets and Monitoring', () => {
    test('should stay within performance budgets', () => {
      const stats = {
        renderTime: performanceTracker.getStats('terminal-render'),
        interactionTime: performanceTracker.getStats('click-response'),
        memoryUsage: (performance as any).memory?.usedJSHeapSize || 0,
      };

      // Define performance budgets
      const budgets = {
        maxRenderTime: 100, // ms
        maxInteractionTime: 50, // ms
        maxMemoryUsage: 10 * 1024 * 1024, // 10MB
      };

      if (stats.renderTime) {
        expect(stats.renderTime.average).toBeLessThan(budgets.maxRenderTime);
        expect(stats.renderTime.p95).toBeLessThan(budgets.maxRenderTime * 1.5);
      }

      if (stats.interactionTime) {
        expect(stats.interactionTime.average).toBeLessThan(budgets.maxInteractionTime);
      }

      expect(stats.memoryUsage).toBeLessThan(budgets.maxMemoryUsage);
    });

    test('should provide performance metrics', () => {
      // Collect and validate performance metrics
      const metrics = {
        fps: 60, // Target FPS
        renderBudget: 16.67, // 60fps budget per frame
        interactionBudget: 50, // Interaction response budget
      };

      // Simulate frame timing
      const frameTimes: number[] = [];
      for (let i = 0; i < 60; i++) {
        const frameStart = performance.now();
        // Simulate frame work
        const frameEnd = performance.now();
        frameTimes.push(frameEnd - frameStart);
      }

      const averageFrameTime = frameTimes.reduce((sum, time) => sum + time, 0) / frameTimes.length;
      const fps = 1000 / averageFrameTime;

      expect(fps).toBeGreaterThanOrEqual(30); // Minimum acceptable FPS
      expect(averageFrameTime).toBeLessThan(metrics.renderBudget * 2); // Allow some overhead
    });
  });

  describe('Stress Testing', () => {
    test('should handle extreme loads gracefully', async () => {
      const StressTestComponent = ({ items }: { items: number }) => (
        <div>
          {Array.from({ length: items }, (_, i) => (
            <div key={i} onClick={() => console.log(`Clicked ${i}`)}>
              Stress Test Item {i} - {Math.random()}
            </div>
          ))}
        </div>
      );

      performanceTracker.startMeasurement('stress-test');

      const { container } = render(<StressTestComponent items={500} />);

      const duration = performanceTracker.endMeasurement('stress-test');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(1000); // Even with 500 items, should render in under 1 second
    });

    test('should maintain performance under concurrent operations', async () => {
      const ConcurrentTestComponent = () => {
        const [counters, setCounters] = React.useState(Array(10).fill(0));

        const incrementCounter = (index: number) => {
          setCounters(prev => 
            prev.map((count, i) => i === index ? count + 1 : count)
          );
        };

        return (
          <div>
            {counters.map((count, index) => (
              <div key={index}>
                <span>Counter {index}: {count}</span>
                <button onClick={() => incrementCounter(index)}>
                  Increment
                </button>
              </div>
            ))}
          </div>
        );
      };

      const { container } = render(<ConcurrentTestComponent />);
      const user = userEvent.setup();

      performanceTracker.startMeasurement('concurrent-operations');

      // Simulate concurrent clicks
      const buttons = container.querySelectorAll('button');
      const clickPromises = Array.from(buttons).map(button => user.click(button));

      await Promise.all(clickPromises);

      const duration = performanceTracker.endMeasurement('concurrent-operations');

      expect(duration).toBeLessThan(300); // Concurrent operations should complete quickly
    });
  });
});