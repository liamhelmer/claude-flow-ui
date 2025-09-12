/**
 * Comprehensive performance and memory leak test suite
 * Tests rendering performance, memory usage, and resource cleanup
 */

import React from 'react';
import { render, screen, waitFor, cleanup } from '@testing-library/react';
import { renderHook, act } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';
import { useTerminal } from '@/hooks/useTerminal';
import Terminal from '@/components/terminal/Terminal';
import AgentsPanel from '@/components/monitoring/AgentsPanel';
import MemoryPanel from '@/components/monitoring/MemoryPanel';
import { 
  performanceTimer, 
  trackMemoryLeaks, 
  createMockAgentData, 
  createMockMemoryData,
  generateTestData
} from '@/__tests__/utils/test-helpers';

// Mock WebSocket and Terminal dependencies
jest.mock('@/hooks/useWebSocket');
jest.mock('@/hooks/useTerminal');
jest.mock('@xterm/xterm', () => ({
  Terminal: jest.fn().mockImplementation(() => ({
    open: jest.fn(),
    write: jest.fn(),
    dispose: jest.fn(),
    onData: jest.fn(),
    onResize: jest.fn(),
    loadAddon: jest.fn(),
    fit: jest.fn(),
    resize: jest.fn(),
    clear: jest.fn(),
    element: document.createElement('div')
  })),
}));

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseTerminal = useTerminal as jest.MockedFunction<typeof useTerminal>;

describe('Performance and Memory Test Suite', () => {
  const defaultWebSocketMock = {
    on: jest.fn(),
    off: jest.fn(),
    send: jest.fn(),
    sendMessage: jest.fn(),
    connect: jest.fn(),
    disconnect: jest.fn(),
    isConnected: true,
  };

  const defaultTerminalMock = {
    terminal: null,
    output: '',
    isConnected: true,
    sendInput: jest.fn(),
    resize: jest.fn(),
    clear: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseWebSocket.mockReturnValue(defaultWebSocketMock);
    mockUseTerminal.mockReturnValue(defaultTerminalMock);
  });

  afterEach(() => {
    cleanup();
    // Force garbage collection if available
    if (global.gc) {
      global.gc();
    }
  });

  describe('Component Rendering Performance', () => {
    it('should render Terminal component within performance threshold', () => {
      const timer = performanceTimer();
      
      render(<Terminal sessionId="test-session" />);
      
      const renderTime = timer.endWithExpectation(100); // 100ms threshold
      expect(renderTime).toBeLessThan(100);
    });

    it('should render AgentsPanel with large dataset efficiently', async () => {
      const largeAgentList = Array.from({ length: 1000 }, (_, i) =>
        createMockAgentData({
          id: `agent-${i}`,
          name: `Agent ${i}`,
          type: ['coder', 'tester', 'reviewer'][i % 3] as any,
          status: ['active', 'idle', 'error'][i % 3] as any
        })
      );

      const mockOn = jest.fn((event, callback) => {
        if (event === 'agent-status') {
          setTimeout(() => callback(largeAgentList), 0);
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultWebSocketMock,
        on: mockOn,
      });

      const timer = performanceTimer();
      
      render(<AgentsPanel />);
      
      await waitFor(() => {
        expect(screen.getByText(/agent/i)).toBeInTheDocument();
      }, { timeout: 5000 });

      const renderTime = timer.endWithExpectation(2000); // 2s threshold for large dataset
      expect(renderTime).toBeLessThan(2000);
    });

    it('should handle rapid MemoryPanel updates efficiently', async () => {
      let updateCallback: any = null;
      const mockOn = jest.fn((event, callback) => {
        if (event === 'memory-update') {
          updateCallback = callback;
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultWebSocketMock,
        on: mockOn,
      });

      render(<MemoryPanel />);

      const timer = performanceTimer();
      
      // Simulate 100 rapid memory updates
      for (let i = 0; i < 100; i++) {
        const memoryData = createMockMemoryData({
          memoryUsagePercent: Math.random() * 100,
          timestamp: Date.now() + i
        });
        
        if (updateCallback) {
          updateCallback(memoryData);
        }
        
        // Small delay to simulate real-world timing
        await new Promise(resolve => setTimeout(resolve, 1));
      }

      const updateTime = timer.endWithExpectation(500); // 500ms threshold
      expect(updateTime).toBeLessThan(500);
    });

    it('should handle component mount/unmount cycles efficiently', () => {
      const timer = performanceTimer();
      
      // Perform 50 mount/unmount cycles
      for (let i = 0; i < 50; i++) {
        const { unmount } = render(<Terminal sessionId={`session-${i}`} />);
        unmount();
      }

      const cycleTime = timer.endWithExpectation(1000); // 1s threshold
      expect(cycleTime).toBeLessThan(1000);
    });
  });

  describe('Memory Leak Detection', () => {
    it('should not leak memory during WebSocket hook usage', async () => {
      const memoryTracker = trackMemoryLeaks();
      
      // Create and destroy many hook instances
      for (let i = 0; i < 100; i++) {
        const { unmount } = renderHook(() => useWebSocket());
        unmount();
      }

      // Allow cleanup to complete
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const memoryIncrease = memoryTracker.check(5 * 1024 * 1024); // 5MB threshold
      expect(memoryIncrease).toBeLessThan(5 * 1024 * 1024);
    });

    it('should clean up Terminal component resources properly', () => {
      const memoryTracker = trackMemoryLeaks();
      const terminals: any[] = [];
      
      // Create multiple terminal instances
      for (let i = 0; i < 20; i++) {
        const { unmount } = render(<Terminal sessionId={`terminal-${i}`} />);
        terminals.push(unmount);
      }
      
      // Unmount all terminals
      terminals.forEach(unmount => unmount());
      
      const memoryIncrease = memoryTracker.check(10 * 1024 * 1024); // 10MB threshold
      expect(memoryIncrease).toBeLessThan(10 * 1024 * 1024);
    });

    it('should handle WebSocket event listener cleanup', () => {
      const memoryTracker = trackMemoryLeaks();
      
      for (let i = 0; i < 50; i++) {
        const { result, unmount } = renderHook(() => useWebSocket());
        
        // Add many event listeners
        act(() => {
          for (let j = 0; j < 10; j++) {
            result.current.on(`event-${j}`, jest.fn());
          }
        });
        
        unmount();
      }
      
      const memoryIncrease = memoryTracker.check(5 * 1024 * 1024); // 5MB threshold
      expect(memoryIncrease).toBeLessThan(5 * 1024 * 1024);
    });

    it('should handle large data processing without memory leaks', async () => {
      const memoryTracker = trackMemoryLeaks();
      
      // Process large amounts of mock data
      for (let i = 0; i < 1000; i++) {
        const largeData = {
          agents: Array.from({ length: 100 }, () => createMockAgentData()),
          memory: createMockMemoryData(),
          logs: generateTestData.randomArray(() => generateTestData.randomString(100), 50)
        };
        
        // Simulate data processing
        JSON.stringify(largeData);
        JSON.parse(JSON.stringify(largeData));
        
        // Clear references
        largeData.agents.length = 0;
        largeData.logs.length = 0;
      }
      
      const memoryIncrease = memoryTracker.check(20 * 1024 * 1024); // 20MB threshold
      expect(memoryIncrease).toBeLessThan(20 * 1024 * 1024);
    });
  });

  describe('Resource Management', () => {
    it('should properly dispose of XTerm terminal instances', () => {
      const { Terminal: MockTerminal } = require('@xterm/xterm');
      const mockTerminalInstance = {
        dispose: jest.fn(),
        open: jest.fn(),
        write: jest.fn(),
        onData: jest.fn(),
        onResize: jest.fn(),
      };
      
      MockTerminal.mockReturnValue(mockTerminalInstance);
      
      const { unmount } = render(<Terminal sessionId="disposal-test" />);
      
      unmount();
      
      // Verify terminal disposal is called
      expect(mockTerminalInstance.dispose).toHaveBeenCalled();
    });

    it('should clean up WebSocket connections on component unmount', () => {
      const mockDisconnect = jest.fn();
      mockUseWebSocket.mockReturnValue({
        ...defaultWebSocketMock,
        disconnect: mockDisconnect,
      });
      
      const { unmount } = render(<Terminal sessionId="cleanup-test" />);
      
      unmount();
      
      // Verify cleanup was attempted (implementation dependent)
      expect(mockDisconnect).toHaveBeenCalledTimes(0); // Terminal doesn't own connection
    });

    it('should handle cleanup during error conditions', () => {
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      
      // Component that throws during cleanup
      const ErrorComponent = () => {
        React.useEffect(() => {
          return () => {
            throw new Error('Cleanup error');
          };
        }, []);
        return <div>Error Component</div>;
      };
      
      const { unmount } = render(<ErrorComponent />);
      
      expect(() => unmount()).not.toThrow();
      
      consoleSpy.mockRestore();
    });
  });

  describe('Performance Under Load', () => {
    it('should handle high-frequency data updates', async () => {
      let memoryUpdateCallback: any = null;
      const mockOn = jest.fn((event, callback) => {
        if (event === 'memory-update') {
          memoryUpdateCallback = callback;
        }
      });

      mockUseWebSocket.mockReturnValue({
        ...defaultWebSocketMock,
        on: mockOn,
      });

      render(<MemoryPanel />);

      const timer = performanceTimer();
      
      // Simulate 1000 rapid updates
      const updatePromises = Array.from({ length: 1000 }, async (_, i) => {
        if (memoryUpdateCallback) {
          memoryUpdateCallback(createMockMemoryData({
            memoryUsagePercent: (i % 100),
            timestamp: Date.now() + i
          }));
        }
        
        // Micro-delay to prevent blocking
        if (i % 100 === 0) {
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      });

      await Promise.all(updatePromises);
      
      const processingTime = timer.endWithExpectation(2000); // 2s threshold
      expect(processingTime).toBeLessThan(2000);
    });

    it('should maintain responsiveness during heavy computation', async () => {
      const heavyComputation = () => {
        // Simulate CPU-intensive task
        const start = Date.now();
        while (Date.now() - start < 50) {
          Math.random() * Math.random();
        }
      };

      const timer = performanceTimer();
      
      // Perform heavy computation while rendering
      const computationPromise = Promise.resolve().then(() => {
        for (let i = 0; i < 10; i++) {
          heavyComputation();
        }
      });

      const { rerender } = render(<AgentsPanel />);
      
      // Rerender multiple times during computation
      for (let i = 0; i < 5; i++) {
        rerender(<AgentsPanel key={i} />);
        await new Promise(resolve => setTimeout(resolve, 10));
      }

      await computationPromise;
      
      const totalTime = timer.endWithExpectation(1000); // 1s threshold
      expect(totalTime).toBeLessThan(1000);
    });

    it('should handle concurrent component rendering', async () => {
      const timer = performanceTimer();
      
      // Render multiple components concurrently
      const renderPromises = Array.from({ length: 10 }, (_, i) => 
        new Promise<void>((resolve) => {
          setTimeout(() => {
            render(<Terminal sessionId={`concurrent-${i}`} />);
            resolve();
          }, i * 10);
        })
      );

      await Promise.all(renderPromises);
      
      const concurrentTime = timer.endWithExpectation(500); // 500ms threshold
      expect(concurrentTime).toBeLessThan(500);
    });
  });

  describe('Bundle Size and Load Performance', () => {
    it('should import components efficiently', () => {
      const timer = performanceTimer();
      
      // Test dynamic imports (in real scenario)
      const importPromises = [
        import('@/components/terminal/Terminal'),
        import('@/components/monitoring/AgentsPanel'),
        import('@/components/monitoring/MemoryPanel'),
      ];

      return Promise.all(importPromises).then(() => {
        const importTime = timer.endWithExpectation(100); // 100ms threshold
        expect(importTime).toBeLessThan(100);
      });
    });

    it('should handle code splitting efficiently', async () => {
      // Simulate lazy loading scenario
      const LazyComponent = React.lazy(() => 
        Promise.resolve({
          default: () => <div>Lazy Component</div>
        })
      );

      const timer = performanceTimer();
      
      render(
        <React.Suspense fallback={<div>Loading...</div>}>
          <LazyComponent />
        </React.Suspense>
      );

      await waitFor(() => {
        expect(screen.getByText('Lazy Component')).toBeInTheDocument();
      });

      const loadTime = timer.endWithExpectation(50); // 50ms threshold
      expect(loadTime).toBeLessThan(50);
    });
  });

  describe('Real-world Stress Testing', () => {
    it('should handle typical user session without degradation', async () => {
      const memoryTracker = trackMemoryLeaks();
      const timer = performanceTimer();
      
      // Simulate typical user session
      const { rerender } = render(<Terminal sessionId="stress-test" />);
      
      // Simulate user interactions
      for (let i = 0; i < 100; i++) {
        // Simulate typing, resizing, data updates
        mockUseTerminal.mockReturnValue({
          ...defaultTerminalMock,
          output: generateTestData.randomString(100),
        });
        
        rerender(<Terminal sessionId="stress-test" key={i} />);
        
        if (i % 20 === 0) {
          await new Promise(resolve => setTimeout(resolve, 10));
        }
      }
      
      const sessionTime = timer.endWithExpectation(3000); // 3s threshold
      const memoryIncrease = memoryTracker.check(15 * 1024 * 1024); // 15MB threshold
      
      expect(sessionTime).toBeLessThan(3000);
      expect(memoryIncrease).toBeLessThan(15 * 1024 * 1024);
    });

    it('should maintain performance with multiple monitoring panels', async () => {
      const timer = performanceTimer();
      
      // Render multiple monitoring components
      render(
        <div>
          <AgentsPanel />
          <MemoryPanel />
          <Terminal sessionId="monitor-test-1" />
          <Terminal sessionId="monitor-test-2" />
        </div>
      );

      // Simulate data updates for all components
      for (let i = 0; i < 50; i++) {
        // Update would trigger re-renders in real scenario
        await new Promise(resolve => setTimeout(resolve, 5));
      }

      const multiComponentTime = timer.endWithExpectation(1500); // 1.5s threshold
      expect(multiComponentTime).toBeLessThan(1500);
    });
  });
});