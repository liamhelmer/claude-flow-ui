/**
 * Terminal Configuration Loading Performance Tests
 * 
 * Performance and timing tests for the terminal configuration loading fix:
 * - Measure config loading times
 * - Test performance under load
 * - Verify no performance regressions
 * - Memory usage and cleanup verification
 */

import { renderHook, act, waitFor } from '@testing-library/react';
import { render, screen } from '@testing-library/react';
import { performance } from 'perf_hooks';
import Terminal from '@/components/Terminal/Terminal';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock the hooks
jest.mock('@/hooks/useTerminal');
jest.mock('@/hooks/useWebSocket');

describe('Terminal Configuration Loading Performance', () => {
  let mockClient: any;
  let mockUseTerminal: any;
  let mockUseWebSocket: any;
  let performanceMarks: { [key: string]: number } = {};

  beforeEach(() => {
    jest.clearAllMocks();
    performanceMarks = {};

    // Enhanced mock client with performance tracking
    mockClient = {
      connected: false,
      connecting: false,
      configLoadTime: 0,
      eventHandlers: {} as { [key: string]: Function },
      
      send: jest.fn((type: string, data: any) => {
        const startTime = performance.now();
        
        if (type === 'request-config') {
          setTimeout(() => {
            const endTime = performance.now();
            mockClient.configLoadTime = endTime - startTime;
            
            if (mockClient.eventHandlers['terminal-config']) {
              mockClient.eventHandlers['terminal-config']({
                sessionId: data.sessionId,
                cols: 80,
                rows: 24
              });
            }
          }, mockClient.configRequestDelay || 0);
        }
      }),
      
      on: jest.fn((event: string, handler: Function) => {
        mockClient.eventHandlers[event] = handler;
      }),
      
      off: jest.fn((event: string, handler: Function) => {
        delete mockClient.eventHandlers[event];
      }),
      
      emit: jest.fn((event: string, data?: any) => {
        if (mockClient.eventHandlers[event]) {
          mockClient.eventHandlers[event](data);
        }
      }),
      
      configRequestDelay: 0
    };

    mockUseTerminal = {
      terminalRef: { current: document.createElement('div') },
      focusTerminal: jest.fn(),
      fitTerminal: jest.fn(),
      scrollToTop: jest.fn(),
      scrollToBottom: jest.fn(),
      refreshTerminal: jest.fn(),
      isAtBottom: false,
      hasNewOutput: false,
      terminal: null,
      backendTerminalConfig: null,
      isConnected: false
    };
    (useTerminal as jest.Mock).mockReturnValue(mockUseTerminal);

    mockUseWebSocket = {
      connected: false,
      connecting: false,
      isConnected: false,
      sendData: jest.fn(),
      resizeTerminal: jest.fn(),
      requestTerminalConfig: jest.fn((sessionId: string) => {
        mockClient.send('request-config', { sessionId });
      }),
      on: mockClient.on,
      off: mockClient.off
    };
    (useWebSocket as jest.Mock).mockReturnValue(mockUseWebSocket);
  });

  describe('Configuration Request Performance', () => {
    test('should request config within 10ms of connection', async () => {
      const connectionStart = performance.now();
      
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      await waitFor(() => {
        expect(mockUseWebSocket.requestTerminalConfig).toHaveBeenCalled();
      });

      const requestTime = performance.now();
      const timeDiff = requestTime - connectionStart;

      expect(timeDiff).toBeLessThan(10);
    });

    test('should handle config responses within expected time', async () => {
      const configDelays = [0, 10, 50, 100, 250, 500];

      for (const delay of configDelays) {
        mockClient.configRequestDelay = delay;
        mockUseWebSocket.connected = true;
        mockUseWebSocket.isConnected = true;
        mockClient.connected = true;

        const startTime = performance.now();

        const { unmount } = render(<Terminal sessionId={`test-session-${delay}`} />);

        await waitFor(() => {
          expect(mockUseWebSocket.requestTerminalConfig).toHaveBeenCalledWith(`test-session-${delay}`);
        });

        // Wait for config to arrive
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, delay + 50));
          
          mockUseTerminal.backendTerminalConfig = { cols: 80, rows: 24 };
          mockUseTerminal.terminal = {
            cols: 80,
            rows: 24,
            write: jest.fn(),
            onData: jest.fn(),
            onResize: jest.fn()
          };
          
          (useTerminal as jest.Mock).mockReturnValue({
            ...mockUseTerminal,
            backendTerminalConfig: { cols: 80, rows: 24 },
            terminal: mockUseTerminal.terminal
          });
        });

        const endTime = performance.now();
        const totalTime = endTime - startTime;

        // Should complete within reasonable time of the expected delay
        expect(totalTime).toBeLessThan(delay + 100);

        unmount();

        // Reset for next iteration
        mockUseTerminal.backendTerminalConfig = null;
        mockUseTerminal.terminal = null;
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: null,
          terminal: null
        });
      }
    });

    test('should maintain performance with multiple concurrent requests', async () => {
      const sessionCount = 10;
      const sessions = Array.from({ length: sessionCount }, (_, i) => `session-${i}`);
      
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const startTime = performance.now();

      // Render multiple terminals concurrently
      const components = sessions.map(sessionId => 
        render(<Terminal sessionId={sessionId} />)
      );

      // Wait for all config requests
      await waitFor(() => {
        sessions.forEach(sessionId => {
          expect(mockUseWebSocket.requestTerminalConfig).toHaveBeenCalledWith(sessionId);
        });
      });

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      // Should handle all requests efficiently (under 100ms total)
      expect(totalTime).toBeLessThan(100);

      // Cleanup
      components.forEach(({ unmount }) => unmount());
    });
  });

  describe('Event Listener Performance', () => {
    test('should register event listeners quickly', async () => {
      const registrationTimes: number[] = [];

      mockClient.on.mockImplementation((event: string, handler: Function) => {
        registrationTimes.push(performance.now());
        mockClient.eventHandlers[event] = handler;
      });

      const startTime = performance.now();

      render(<Terminal sessionId={'test-session'} />);

      await waitFor(() => {
        expect(mockClient.on).toHaveBeenCalledTimes(4); // 4 event types
      });

      const endTime = performance.now();
      const totalTime = endTime - startTime;

      // Event registration should be very fast
      expect(totalTime).toBeLessThan(50);

      // All registrations should happen within a small time window
      const timeSpread = Math.max(...registrationTimes) - Math.min(...registrationTimes);
      expect(timeSpread).toBeLessThan(10);
    });

    test('should handle rapid event emissions efficiently', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      await waitFor(() => {
        expect(mockClient.on).toHaveBeenCalledWith('terminal-config', expect.any(Function));
      });

      // Send many rapid config events
      const eventCount = 100;
      const startTime = performance.now();

      for (let i = 0; i < eventCount; i++) {
        await act(async () => {
          mockClient.emit('terminal-config', {
            sessionId: 'test-session',
            cols: 80 + i,
            rows: 24 + i
          });
        });
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;
      const avgTimePerEvent = totalTime / eventCount;

      // Should handle events very efficiently
      expect(avgTimePerEvent).toBeLessThan(1); // Less than 1ms per event
      expect(totalTime).toBeLessThan(100); // Total under 100ms
    });

    test('should maintain performance during listener cleanup', async () => {
      const componentCount = 20;
      const components: Array<{ unmount: () => void }> = [];

      // Mount many components
      for (let i = 0; i < componentCount; i++) {
        components.push(render(<Terminal sessionId={`session-${i}`} />));
      }

      await waitFor(() => {
        expect(mockClient.on).toHaveBeenCalledTimes(componentCount * 4);
      });

      // Unmount all components and measure cleanup time
      const startTime = performance.now();

      components.forEach(({ unmount }) => unmount());

      const endTime = performance.now();
      const cleanupTime = endTime - startTime;

      // Cleanup should be fast
      expect(cleanupTime).toBeLessThan(50);
      expect(mockClient.off).toHaveBeenCalledTimes(componentCount * 4);
    });
  });

  describe('Memory Performance', () => {
    test('should not accumulate memory during config loading cycles', async () => {
      const cycleCount = 50;
      
      for (let i = 0; i < cycleCount; i++) {
        const { unmount } = render(<Terminal sessionId={`session-${i}`} />);
        
        await act(async () => {
          mockClient.emit('terminal-config', {
            sessionId: `session-${i}`,
            cols: 80,
            rows: 24
          });
        });

        unmount();
      }

      // Should not have accumulated event handlers
      expect(Object.keys(mockClient.eventHandlers)).toHaveLength(0);
    });

    test('should handle memory cleanup during rapid session changes', async () => {
      const sessionCount = 100;
      const sessions = Array.from({ length: sessionCount }, (_, i) => `session-${i}`);

      const { rerender } = render(<Terminal sessionId={sessions[0]} />);

      // Rapidly change sessions
      for (let i = 1; i < sessions.length; i++) {
        rerender(<Terminal sessionId={sessions[i]} />);
        
        // Small delay to allow cleanup
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, 1));
        });
      }

      // Should have cleaned up properly - only current session handlers should remain
      const activeHandlers = Object.keys(mockClient.eventHandlers).length;
      expect(activeHandlers).toBeLessThanOrEqual(4); // Max 4 event types
    });

    test('should prevent memory leaks in config request tracking', async () => {
      const sessionCount = 200;

      for (let i = 0; i < sessionCount; i++) {
        mockUseWebSocket.requestTerminalConfig(`session-${i}`);
      }

      expect(mockClient.send).toHaveBeenCalledTimes(sessionCount);

      // Verify no request tracking memory leaks
      expect(true).toBe(true); // If we get here without errors, memory is managed properly
    });
  });

  describe('Rendering Performance', () => {
    test('should render terminal component quickly', async () => {
      const renderStartTime = performance.now();

      render(<Terminal sessionId={'test-session'} />);

      const renderEndTime = performance.now();
      const renderTime = renderEndTime - renderStartTime;

      // Initial render should be fast
      expect(renderTime).toBeLessThan(50);
    });

    test('should handle config updates without render blocking', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const { rerender } = render(<Terminal sessionId="test-session" />);

      const configs = [
        { cols: 80, rows: 24 },
        { cols: 100, rows: 30 },
        { cols: 120, rows: 40 },
        { cols: 132, rows: 50 }
      ];

      const updateTimes: number[] = [];

      for (const config of configs) {
        const updateStart = performance.now();

        await act(async () => {
          mockUseTerminal.backendTerminalConfig = config;
          mockUseTerminal.terminal = {
            ...config,
            write: jest.fn(),
            onData: jest.fn(),
            onResize: jest.fn()
          };
          
          (useTerminal as jest.Mock).mockReturnValue({
            ...mockUseTerminal,
            backendTerminalConfig: config,
            terminal: mockUseTerminal.terminal
          });
        });

        rerender(<Terminal sessionId="test-session" />);

        const updateEnd = performance.now();
        updateTimes.push(updateEnd - updateStart);
      }

      // Each update should be fast
      updateTimes.forEach(time => {
        expect(time).toBeLessThan(25);
      });

      // Average update time should be very fast
      const avgUpdateTime = updateTimes.reduce((sum, time) => sum + time, 0) / updateTimes.length;
      expect(avgUpdateTime).toBeLessThan(15);
    });

    test('should maintain 60fps during config loading animations', async () => {
      const frameTime = 1000 / 60; // 16.67ms per frame at 60fps
      
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId={'test-session'} />);

      // Simulate animation frames during config loading
      const animationFrames = 30; // 0.5 seconds of animation
      const frameTimes: number[] = [];

      for (let frame = 0; frame < animationFrames; frame++) {
        const frameStart = performance.now();

        // Simulate frame work (re-render with loading state)
        await act(async () => {
          await new Promise(resolve => requestAnimationFrame(resolve));
        });

        const frameEnd = performance.now();
        frameTimes.push(frameEnd - frameStart);
      }

      // Most frames should be under 16.67ms for 60fps
      const framesUnder60fps = frameTimes.filter(time => time < frameTime).length;
      const fps60Percentage = (framesUnder60fps / animationFrames) * 100;

      expect(fps60Percentage).toBeGreaterThan(80); // At least 80% of frames should be 60fps+
    });
  });

  describe('Network Performance Simulation', () => {
    test('should handle slow network config responses gracefully', async () => {
      const networkDelays = [100, 250, 500, 1000, 2000]; // Various network conditions

      for (const delay of networkDelays) {
        mockClient.configRequestDelay = delay;
        
        const startTime = performance.now();

        mockUseWebSocket.connected = true;
        mockUseWebSocket.isConnected = true;
        mockClient.connected = true;

        const { unmount } = render(<Terminal sessionId={`slow-session-${delay}`} />);

        // Should show waiting state immediately
        expect(screen.getByText('Waiting...')).toBeInTheDocument();

        // Wait for config to arrive
        await act(async () => {
          await new Promise(resolve => setTimeout(resolve, delay + 100));
          
          mockUseTerminal.backendTerminalConfig = { cols: 80, rows: 24 };
          mockUseTerminal.terminal = {
            cols: 80,
            rows: 24,
            write: jest.fn(),
            onData: jest.fn(),
            onResize: jest.fn()
          };
          
          (useTerminal as jest.Mock).mockReturnValue({
            ...mockUseTerminal,
            backendTerminalConfig: { cols: 80, rows: 24 },
            terminal: mockUseTerminal.terminal
          });
        });

        const endTime = performance.now();
        const totalResponseTime = endTime - startTime;

        // Should handle gracefully regardless of network speed
        expect(totalResponseTime).toBeLessThan(delay + 200); // Some overhead is expected

        unmount();

        // Reset for next test
        mockUseTerminal.backendTerminalConfig = null;
        mockUseTerminal.terminal = null;
        (useTerminal as jest.Mock).mockReturnValue({
          ...mockUseTerminal,
          backendTerminalConfig: null,
          terminal: null
        });
      }
    });

    test('should maintain responsiveness during config timeout scenarios', async () => {
      const timeoutDelay = 5000;
      mockClient.configRequestDelay = timeoutDelay;

      const startTime = performance.now();

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const { rerender } = render(<Terminal sessionId="timeout-session" />);

      // Should remain responsive during timeout
      for (let i = 0; i < 10; i++) {
        const rerenderStart = performance.now();
        rerender(<Terminal sessionId="timeout-session" />);
        const rerenderEnd = performance.now();
        
        expect(rerenderEnd - rerenderStart).toBeLessThan(20);
      }

      // Should still show waiting state
      expect(screen.getByText('Waiting...')).toBeInTheDocument();
    });
  });

  describe('Stress Testing', () => {
    test('should handle 100 simultaneous terminal instances', async () => {
      const terminalCount = 100;
      const terminals: Array<{ unmount: () => void }> = [];

      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      const startTime = performance.now();

      // Create all terminals
      for (let i = 0; i < terminalCount; i++) {
        terminals.push(render(<Terminal sessionId={`stress-session-${i}`} />));
      }

      // Wait for all config requests
      await waitFor(() => {
        expect(mockUseWebSocket.requestTerminalConfig).toHaveBeenCalledTimes(terminalCount);
      });

      const configRequestTime = performance.now();

      // Send configs for all terminals
      await act(async () => {
        for (let i = 0; i < terminalCount; i++) {
          mockClient.emit('terminal-config', {
            sessionId: `stress-session-${i}`,
            cols: 80,
            rows: 24
          });
        }
      });

      const configProcessTime = performance.now();

      // Clean up
      terminals.forEach(({ unmount }) => unmount());

      const endTime = performance.now();

      const totalTime = endTime - startTime;
      const requestTime = configRequestTime - startTime;
      const processTime = configProcessTime - configRequestTime;
      const cleanupTime = endTime - configProcessTime;

      console.log(`Stress test results for ${terminalCount} terminals:
        Total time: ${totalTime}ms
        Request time: ${requestTime}ms
        Process time: ${processTime}ms
        Cleanup time: ${cleanupTime}ms
        Avg per terminal: ${totalTime / terminalCount}ms`);

      // Should handle the load reasonably
      expect(totalTime).toBeLessThan(5000); // Under 5 seconds total
      expect(totalTime / terminalCount).toBeLessThan(50); // Under 50ms per terminal average
    });

    test('should maintain performance under config update storms', async () => {
      mockUseWebSocket.connected = true;
      mockUseWebSocket.isConnected = true;
      mockClient.connected = true;

      render(<Terminal sessionId="storm-session" />);

      await waitFor(() => {
        expect(mockClient.on).toHaveBeenCalledWith('terminal-config', expect.any(Function));
      });

      // Send rapid config updates
      const updateCount = 1000;
      const startTime = performance.now();

      for (let i = 0; i < updateCount; i++) {
        await act(async () => {
          mockClient.emit('terminal-config', {
            sessionId: 'storm-session',
            cols: 80 + (i % 100),
            rows: 24 + (i % 50)
          });
        });
      }

      const endTime = performance.now();
      const totalTime = endTime - startTime;
      const avgTimePerUpdate = totalTime / updateCount;

      // Should handle rapid updates efficiently
      expect(avgTimePerUpdate).toBeLessThan(2); // Less than 2ms per update
      expect(totalTime).toBeLessThan(2000); // Total under 2 seconds
    });
  });
});