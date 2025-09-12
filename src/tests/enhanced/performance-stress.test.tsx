/**
 * @jest-environment jsdom
 */

import { render, act, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import React from 'react';

import { Terminal } from '@/components/terminal/Terminal';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { TabList } from '@/components/tabs/TabList';
import { MonitoringSidebar } from '@/components/monitoring/MonitoringSidebar';
import { 
  TestDataGenerator, 
  TestPerformanceTracker,
  PerformanceTestUtils,
  renderWithEnhancements 
} from './test-utilities';

// Mock dependencies with performance tracking
jest.mock('@/hooks/useTerminal', () => ({
  useTerminal: () => ({
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
  }),
}));

jest.mock('@/hooks/useWebSocket', () => ({
  useWebSocket: () => ({
    sendData: jest.fn(),
    resizeTerminal: jest.fn(),
    isConnected: true,
    on: jest.fn(),
    off: jest.fn(),
  }),
}));

jest.mock('@/lib/state/store', () => ({
  useAppStore: () => ({
    sessions: TestDataGenerator.generateSessions(100),
    activeSession: null,
    isLoading: false,
    error: null,
    agents: TestDataGenerator.generateAgents(50),
    memory: TestDataGenerator.generateMemoryData(),
    commands: TestDataGenerator.generateCommands(1000),
    prompts: [],
    addSession: jest.fn(),
    removeSession: jest.fn(),
    setActiveSession: jest.fn(),
  }),
}));

describe('Performance Stress Testing', () => {
  let performanceTracker: TestPerformanceTracker;

  beforeEach(() => {
    performanceTracker = new TestPerformanceTracker();
    jest.clearAllMocks();
  });

  afterEach(() => {
    performanceTracker.reset();
  });

  describe('Large Dataset Rendering', () => {
    test('should render thousands of sessions efficiently', async () => {
      const sessionCounts = [100, 500, 1000, 2000];

      for (const count of sessionCounts) {
        const sessions = TestDataGenerator.generateSessions(count);
        
        performanceTracker.startMeasurement(`sessions-${count}`);
        
        const { container } = renderWithEnhancements(
          <Sidebar
            sessions={sessions}
            activeSessionId="session-0"
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
        );

        const duration = performanceTracker.endMeasurement(`sessions-${count}`);
        
        expect(container).toBeInTheDocument();
        // Performance should scale reasonably
        expect(duration).toBeLessThan(count * 0.5); // Max 0.5ms per session
      }

      // Check that performance doesn't degrade exponentially
      const stats100 = performanceTracker.getStats('sessions-100');
      const stats1000 = performanceTracker.getStats('sessions-1000');
      const stats2000 = performanceTracker.getStats('sessions-2000');

      if (stats100 && stats1000 && stats2000) {
        // 10x more items should not take 100x longer
        expect(stats1000.average / stats100.average).toBeLessThan(20);
        expect(stats2000.average / stats1000.average).toBeLessThan(5);
      }
    });

    test('should handle massive tab lists efficiently', async () => {
      const tabCounts = [50, 100, 200, 500];

      for (const count of tabCounts) {
        const tabs = Array.from({ length: count }, (_, i) => ({
          id: `tab-${i}`,
          title: `Tab ${i} - ${Math.random().toString(36).substring(7)}`,
          isActive: i === 0,
        }));

        performanceTracker.startMeasurement(`tabs-${count}`);

        const { container } = renderWithEnhancements(
          <TabList tabs={tabs} onTabChange={jest.fn()} />
        );

        const duration = performanceTracker.endMeasurement(`tabs-${count}`);

        expect(container).toBeInTheDocument();
        expect(duration).toBeLessThan(count * 0.3); // Max 0.3ms per tab
      }
    });

    test('should maintain performance with complex nested data', async () => {
      const complexData = TestDataGenerator.generateLargeDataset(1000);

      const ComplexDataComponent = ({ data }: { data: any[] }) => (
        <div>
          {data.map((item, index) => (
            <div key={index} className="border p-2 mb-1">
              <h3>{item.name}</h3>
              <p>{item.description}</p>
              <div>
                Tags: {item.metadata.tags.join(', ')}
              </div>
              <div>Priority: {item.metadata.priority}</div>
              <ul>
                {item.nestedData.map((nested: any, nestedIndex: number) => (
                  <li key={nestedIndex}>
                    {nested.label}: {nested.value.toFixed(2)}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      );

      performanceTracker.startMeasurement('complex-data-render');

      const { container } = renderWithEnhancements(
        <ComplexDataComponent data={complexData} />
      );

      const duration = performanceTracker.endMeasurement('complex-data-render');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(2000); // Should render 1000 complex items in under 2 seconds
    });
  });

  describe('Memory Pressure Testing', () => {
    test('should handle memory pressure without performance degradation', async () => {
      // Create initial memory pressure
      PerformanceTestUtils.createMemoryPressure();

      const sessions = TestDataGenerator.generateSessions(500);

      performanceTracker.startMeasurement('memory-pressure-render');

      const { container } = renderWithEnhancements(
        <Sidebar
          sessions={sessions}
          activeSessionId="session-0"
          onSessionSelect={jest.fn()}
          onSessionClose={jest.fn()}
          onNewSession={jest.fn()}
        />
      );

      const duration = performanceTracker.endMeasurement('memory-pressure-render');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(1000); // Should still render reasonably fast under memory pressure
    });

    test('should efficiently clean up large component trees', () => {
      const sessions = TestDataGenerator.generateSessions(1000);

      performanceTracker.startMeasurement('large-unmount');

      const { unmount } = renderWithEnhancements(
        <div>
          <Sidebar
            sessions={sessions}
            activeSessionId="session-0"
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
          <MonitoringSidebar />
          <Terminal sessionId="test-session" />
        </div>
      );

      unmount();

      const duration = performanceTracker.endMeasurement('large-unmount');

      expect(duration).toBeLessThan(500); // Large unmount should be fast
    });

    test('should handle rapid mount/unmount cycles efficiently', async () => {
      const cycleCount = 100;
      const sessions = TestDataGenerator.generateSessions(50);

      performanceTracker.startMeasurement('mount-unmount-cycles');

      for (let i = 0; i < cycleCount; i++) {
        const { unmount } = renderWithEnhancements(
          <Sidebar
            sessions={sessions}
            activeSessionId={`session-${i % sessions.length}`}
            onSessionSelect={jest.fn()}
            onSessionClose={jest.fn()}
            onNewSession={jest.fn()}
          />
        );
        unmount();
      }

      const duration = performanceTracker.endMeasurement('mount-unmount-cycles');

      expect(duration).toBeLessThan(cycleCount * 10); // Average 10ms per cycle max
    });
  });

  describe('High Frequency Updates', () => {
    test('should handle rapid state updates efficiently', async () => {
      const HighFrequencyComponent = () => {
        const [counter, setCounter] = React.useState(0);
        const [data, setData] = React.useState<number[]>([]);

        React.useEffect(() => {
          const interval = setInterval(() => {
            setCounter(prev => prev + 1);
            setData(prev => [...prev.slice(-99), Math.random()]); // Keep last 100 items
          }, 10); // Update every 10ms

          return () => clearInterval(interval);
        }, []);

        return (
          <div>
            <div>Counter: {counter}</div>
            <div>
              {data.map((value, index) => (
                <span key={index}>{value.toFixed(2)} </span>
              ))}
            </div>
          </div>
        );
      };

      performanceTracker.startMeasurement('high-frequency-updates');

      const { container } = renderWithEnhancements(<HighFrequencyComponent />);

      // Let it run for 500ms (50 updates)
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 500));
      });

      const duration = performanceTracker.endMeasurement('high-frequency-updates');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(1000); // Should handle rapid updates smoothly
    });

    test('should batch multiple state updates efficiently', async () => {
      const BatchedUpdatesComponent = () => {
        const [state, setState] = React.useState({
          counter1: 0,
          counter2: 0,
          counter3: 0,
          data: [] as number[],
        });

        const performBatchedUpdates = React.useCallback(() => {
          // Multiple updates that should be batched
          setState(prev => ({ ...prev, counter1: prev.counter1 + 1 }));
          setState(prev => ({ ...prev, counter2: prev.counter2 + 2 }));
          setState(prev => ({ ...prev, counter3: prev.counter3 + 3 }));
          setState(prev => ({ ...prev, data: [...prev.data, Math.random()] }));
        }, []);

        return (
          <div>
            <button onClick={performBatchedUpdates}>Update All</button>
            <div>C1: {state.counter1}, C2: {state.counter2}, C3: {state.counter3}</div>
            <div>Data length: {state.data.length}</div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<BatchedUpdatesComponent />);
      const updateButton = await waitFor(() => screen.getByRole('button', { name: /update all/i }));

      performanceTracker.startMeasurement('batched-updates');

      // Perform many rapid updates
      for (let i = 0; i < 100; i++) {
        await user.click(updateButton);
      }

      const duration = performanceTracker.endMeasurement('batched-updates');

      expect(duration).toBeLessThan(2000); // 100 batched updates should be fast
    });

    test('should handle WebSocket message flood efficiently', async () => {
      const mockWebSocket = {
        sendData: jest.fn(),
        resizeTerminal: jest.fn(),
        isConnected: true,
        on: jest.fn(),
        off: jest.fn(),
      };

      // Override the mock for this test
      jest.doMock('@/hooks/useWebSocket', () => ({
        useWebSocket: () => mockWebSocket,
      }));

      const WebSocketFloodComponent = () => {
        const [messages, setMessages] = React.useState<string[]>([]);

        React.useEffect(() => {
          // Simulate rapid WebSocket messages
          const interval = setInterval(() => {
            setMessages(prev => [
              ...prev.slice(-99), // Keep last 100 messages
              `Message ${Date.now()}`
            ]);
          }, 5); // New message every 5ms

          return () => clearInterval(interval);
        }, []);

        return (
          <div>
            <Terminal sessionId="flood-test" />
            <div>
              {messages.map((msg, index) => (
                <div key={index}>{msg}</div>
              ))}
            </div>
          </div>
        );
      };

      performanceTracker.startMeasurement('websocket-flood');

      const { container } = renderWithEnhancements(<WebSocketFloodComponent />);

      // Let message flood run for 300ms
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 300));
      });

      const duration = performanceTracker.endMeasurement('websocket-flood');

      expect(container).toBeInTheDocument();
      expect(duration).toBeLessThan(800); // Should handle message flood efficiently
    });
  });

  describe('CPU Intensive Operations', () => {
    test('should remain responsive during CPU intensive tasks', async () => {
      const CpuIntensiveComponent = () => {
        const [result, setResult] = React.useState<number>(0);
        const [isCalculating, setIsCalculating] = React.useState(false);

        const performHeavyCalculation = React.useCallback(async () => {
          setIsCalculating(true);
          
          // Simulate CPU intensive work in chunks to maintain responsiveness
          let sum = 0;
          const chunkSize = 10000;
          const totalIterations = 1000000;

          for (let i = 0; i < totalIterations; i += chunkSize) {
            const chunkEnd = Math.min(i + chunkSize, totalIterations);
            
            // Perform calculation chunk
            for (let j = i; j < chunkEnd; j++) {
              sum += Math.sqrt(j) * Math.sin(j);
            }

            // Yield control back to browser between chunks
            if (i % (chunkSize * 10) === 0) {
              await new Promise(resolve => setTimeout(resolve, 0));
            }
          }

          setResult(sum);
          setIsCalculating(false);
        }, []);

        return (
          <div>
            <button onClick={performHeavyCalculation} disabled={isCalculating}>
              {isCalculating ? 'Calculating...' : 'Start Heavy Calculation'}
            </button>
            <div>Result: {result.toExponential(2)}</div>
            <div>Status: {isCalculating ? 'Working...' : 'Ready'}</div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<CpuIntensiveComponent />);

      const button = screen.getByRole('button');
      
      performanceTracker.startMeasurement('cpu-intensive');

      await user.click(button);

      // Wait for calculation to complete
      await waitFor(() => {
        expect(screen.getByText('Ready')).toBeInTheDocument();
      }, { timeout: 10000 });

      const duration = performanceTracker.endMeasurement('cpu-intensive');

      // Should complete in reasonable time and remain responsive
      expect(duration).toBeLessThan(10000);
      expect(screen.getByText(/result:/i)).toBeInTheDocument();
    });

    test('should handle concurrent CPU intensive operations', async () => {
      const ConcurrentCpuComponent = () => {
        const [workers, setWorkers] = React.useState<{ id: number; status: string; result: number }[]>([]);

        const startWorker = (id: number) => {
          setWorkers(prev => [
            ...prev.filter(w => w.id !== id),
            { id, status: 'working', result: 0 }
          ]);

          // Simulate async CPU work
          setTimeout(() => {
            let result = 0;
            for (let i = 0; i < 100000; i++) {
              result += Math.random() * Math.sqrt(i);
            }

            setWorkers(prev => prev.map(w => 
              w.id === id ? { ...w, status: 'completed', result } : w
            ));
          }, Math.random() * 100 + 50);
        };

        return (
          <div>
            <button onClick={() => {
              for (let i = 0; i < 5; i++) {
                startWorker(i);
              }
            }}>
              Start 5 Concurrent Workers
            </button>
            <div>
              {workers.map(worker => (
                <div key={worker.id}>
                  Worker {worker.id}: {worker.status} - {worker.result.toFixed(2)}
                </div>
              ))}
            </div>
          </div>
        );
      };

      const { user } = renderWithEnhancements(<ConcurrentCpuComponent />);

      const startButton = screen.getByRole('button');

      performanceTracker.startMeasurement('concurrent-cpu');

      await user.click(startButton);

      // Wait for all workers to complete
      await waitFor(() => {
        const completedWorkers = screen.getAllByText(/completed/i);
        return completedWorkers.length >= 5;
      }, { timeout: 5000 });

      const duration = performanceTracker.endMeasurement('concurrent-cpu');

      expect(duration).toBeLessThan(5000);
      expect(screen.getAllByText(/completed/i)).toHaveLength(5);
    });
  });

  describe('Performance Budgets and Monitoring', () => {
    test('should meet performance budgets across all scenarios', () => {
      const allStats = {
        sessions100: performanceTracker.getStats('sessions-100'),
        sessions1000: performanceTracker.getStats('sessions-1000'),
        tabs50: performanceTracker.getStats('tabs-50'),
        tabs200: performanceTracker.getStats('tabs-200'),
        complexData: performanceTracker.getStats('complex-data-render'),
        mountUnmount: performanceTracker.getStats('mount-unmount-cycles'),
        highFrequency: performanceTracker.getStats('high-frequency-updates'),
      };

      // Define strict performance budgets
      const budgets = {
        'sessions-100': 200,    // 100 sessions should render in <200ms
        'sessions-1000': 1000,  // 1000 sessions should render in <1s
        'tabs-50': 100,         // 50 tabs should render in <100ms
        'tabs-200': 400,        // 200 tabs should render in <400ms
        'complex-data-render': 2000, // Complex data in <2s
        'mount-unmount-cycles': 1000, // Mount/unmount cycles in <1s
        'high-frequency-updates': 1000, // High frequency updates in <1s
      };

      Object.entries(budgets).forEach(([metric, budget]) => {
        const stats = performanceTracker.getStats(metric);
        if (stats) {
          expect(stats.average).toBeLessThan(budget);
          expect(stats.p95).toBeLessThan(budget * 1.5); // P95 can be 50% higher
          expect(stats.max).toBeLessThan(budget * 2); // Max can be 100% higher
        }
      });
    });

    test('should provide comprehensive performance metrics', () => {
      // Collect real-time performance metrics
      const performanceEntry = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming;
      
      const metrics = {
        domContentLoaded: performanceEntry?.domContentLoadedEventEnd - performanceEntry?.domContentLoadedEventStart,
        loadComplete: performanceEntry?.loadEventEnd - performanceEntry?.loadEventStart,
        memoryUsage: (performance as any).memory?.usedJSHeapSize || 0,
        renderCount: performanceTracker.getStats('sessions-100')?.count || 0,
      };

      // Validate metrics are within acceptable ranges
      if (metrics.domContentLoaded) {
        expect(metrics.domContentLoaded).toBeLessThan(2000); // DOM ready in <2s
      }
      
      if (metrics.loadComplete) {
        expect(metrics.loadComplete).toBeLessThan(3000); // Full load in <3s
      }

      expect(metrics.memoryUsage).toBeLessThan(50 * 1024 * 1024); // <50MB memory usage
      expect(metrics.renderCount).toBeGreaterThan(0); // Should have performed renders
    });
  });
});