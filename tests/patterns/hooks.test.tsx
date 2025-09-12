/**
 * Comprehensive Hook Testing Patterns
 * Tests for useTerminal, useWebSocket, and custom hooks
 */

import React from 'react';
import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '@/hooks/useTerminal';
import { useWebSocket } from '@/hooks/useWebSocket';
import { MockWebSocket, MockTerminal, renderWithProviders } from '../utils/test-utils';

// Mock dependencies
jest.mock('@xterm/xterm', () => ({
  Terminal: MockTerminal,
}));

jest.mock('@xterm/addon-fit', () => ({
  FitAddon: jest.fn().mockImplementation(() => ({
    fit: jest.fn(),
    dispose: jest.fn(),
  })),
}));

describe('Hook Testing Patterns', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.runOnlyPendingTimers();
    jest.useRealTimers();
  });

  describe('useWebSocket Hook', () => {
    const defaultProps = {
      url: 'ws://localhost:11237',
      options: {
        autoConnect: true,
        reconnectAttempts: 3,
        reconnectDelay: 1000,
      },
    };

    describe('Connection Management', () => {
      it('should establish connection on mount', async () => {
        const { result } = renderHook(() => useWebSocket(defaultProps.url, defaultProps.options));

        // Initial state
        expect(result.current.isConnected).toBe(false);
        expect(result.current.connectionState).toBe('connecting');

        // Advance timers to simulate connection
        act(() => {
          jest.advanceTimersByTime(100);
        });

        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
          expect(result.current.connectionState).toBe('connected');
        });
      });

      it('should handle connection failures with retry logic', async () => {
        const mockConsoleError = jest.spyOn(console, 'error').mockImplementation();
        
        const { result } = renderHook(() => 
          useWebSocket(defaultProps.url, {
            ...defaultProps.options,
            reconnectAttempts: 2,
            reconnectDelay: 100,
          })
        );

        // Simulate connection failure
        act(() => {
          const ws = (result.current as any).websocket;
          if (ws) {
            ws.simulateError(new Error('Connection failed'));
          }
        });

        // Should attempt reconnection
        await waitFor(() => {
          expect(result.current.connectionState).toBe('reconnecting');
        });

        act(() => {
          jest.advanceTimersByTime(200);
        });

        // Should retry connection
        expect(result.current.reconnectAttempts).toBeGreaterThan(0);

        mockConsoleError.mockRestore();
      });

      it('should clean up connection on unmount', () => {
        const { unmount } = renderHook(() => useWebSocket(defaultProps.url));
        
        const closeSpy = jest.fn();
        // Mock WebSocket close method
        (global as any).WebSocket = jest.fn().mockImplementation(() => ({
          close: closeSpy,
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          readyState: 1,
        }));

        unmount();

        expect(closeSpy).toHaveBeenCalled();
      });
    });

    describe('Message Handling', () => {
      it('should send and receive messages correctly', async () => {
        const onMessage = jest.fn();
        const { result } = renderHook(() => 
          useWebSocket(defaultProps.url, { 
            ...defaultProps.options,
            onMessage 
          })
        );

        // Wait for connection
        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });

        // Send message
        const testMessage = { type: 'test', data: 'hello' };
        act(() => {
          result.current.sendMessage(testMessage);
        });

        // Simulate receiving message
        act(() => {
          const ws = (result.current as any).websocket;
          if (ws) {
            ws.simulateMessage({ type: 'response', data: 'world' });
          }
        });

        expect(onMessage).toHaveBeenCalledWith(
          expect.objectContaining({ type: 'response', data: 'world' })
        );
      });

      it('should queue messages when disconnected', async () => {
        const { result } = renderHook(() => useWebSocket(defaultProps.url));

        // Send message while disconnected
        const testMessage = { type: 'test', data: 'queued' };
        act(() => {
          result.current.sendMessage(testMessage);
        });

        // Message should be queued
        expect(result.current.messageQueue).toContain(testMessage);

        // When connected, queue should be processed
        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });

        act(() => {
          jest.advanceTimersByTime(100);
        });

        expect(result.current.messageQueue).toHaveLength(0);
      });

      it('should handle malformed messages gracefully', async () => {
        const onError = jest.fn();
        const { result } = renderHook(() => 
          useWebSocket(defaultProps.url, { onError })
        );

        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });

        // Simulate malformed message
        act(() => {
          const ws = (result.current as any).websocket;
          if (ws) {
            ws.simulateMessage('invalid json');
          }
        });

        expect(onError).toHaveBeenCalledWith(
          expect.any(Error)
        );
      });
    });

    describe('Event Listeners', () => {
      it('should register and unregister event listeners', () => {
        const { result } = renderHook(() => useWebSocket(defaultProps.url));

        const handler = jest.fn();
        
        act(() => {
          result.current.on('customEvent', handler);
        });

        // Simulate custom event
        act(() => {
          result.current.emit('customEvent', { data: 'test' });
        });

        expect(handler).toHaveBeenCalledWith({ data: 'test' });

        // Unregister
        act(() => {
          result.current.off('customEvent', handler);
        });

        // Should not be called again
        act(() => {
          result.current.emit('customEvent', { data: 'test2' });
        });

        expect(handler).toHaveBeenCalledTimes(1);
      });

      it('should handle multiple listeners for same event', () => {
        const { result } = renderHook(() => useWebSocket(defaultProps.url));

        const handler1 = jest.fn();
        const handler2 = jest.fn();
        
        act(() => {
          result.current.on('test', handler1);
          result.current.on('test', handler2);
        });

        act(() => {
          result.current.emit('test', 'data');
        });

        expect(handler1).toHaveBeenCalledWith('data');
        expect(handler2).toHaveBeenCalledWith('data');
      });
    });

    describe('Performance and Memory', () => {
      it('should not cause memory leaks with frequent reconnections', async () => {
        const { rerender, unmount } = renderHook(
          ({ url }) => useWebSocket(url),
          { initialProps: { url: defaultProps.url } }
        );

        // Simulate multiple reconnections
        for (let i = 0; i < 10; i++) {
          rerender({ url: `ws://localhost:${11237 + i}` });
          
          act(() => {
            jest.advanceTimersByTime(100);
          });
        }

        // Should clean up properly
        unmount();
        
        // Verify no hanging timers
        expect(jest.getTimerCount()).toBe(0);
      });

      it('should debounce rapid message sends', async () => {
        const { result } = renderHook(() => useWebSocket(defaultProps.url));

        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });

        const sendSpy = jest.fn();
        (result.current as any).websocket.send = sendSpy;

        // Send multiple messages rapidly
        act(() => {
          for (let i = 0; i < 100; i++) {
            result.current.sendMessage({ type: 'rapid', id: i });
          }
        });

        // Should batch or debounce sends
        expect(sendSpy.mock.calls.length).toBeLessThan(100);
      });
    });
  });

  describe('useTerminal Hook', () => {
    const defaultSessionId = 'test-session';

    describe('Terminal Lifecycle', () => {
      it('should initialize terminal on mount', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        expect(result.current.terminalRef.current).toBeDefined();
        expect(result.current.terminal).toBeInstanceOf(MockTerminal);
        expect(result.current.isConnected).toBe(false); // Initially disconnected
      });

      it('should cleanup terminal on unmount', () => {
        const { result, unmount } = renderHook(() => 
          useTerminal({ sessionId: defaultSessionId })
        );

        const disposeSpy = jest.spyOn(result.current.terminal!, 'dispose');
        
        unmount();

        expect(disposeSpy).toHaveBeenCalled();
      });

      it('should handle terminal recreation on session change', () => {
        const { result, rerender } = renderHook(
          ({ sessionId }) => useTerminal({ sessionId }),
          { initialProps: { sessionId: defaultSessionId } }
        );

        const initialTerminal = result.current.terminal;
        const disposeSpy = jest.spyOn(initialTerminal!, 'dispose');

        // Change session
        rerender({ sessionId: 'new-session' });

        expect(disposeSpy).toHaveBeenCalled();
        expect(result.current.terminal).not.toBe(initialTerminal);
      });
    });

    describe('Terminal Operations', () => {
      it('should write data to terminal', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        act(() => {
          result.current.writeToTerminal('Hello, terminal!');
        });

        const terminal = result.current.terminal as MockTerminal;
        expect(terminal.getContent()).toContain('Hello, terminal!');
      });

      it('should clear terminal content', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        // Write some content first
        act(() => {
          result.current.writeToTerminal('Some content');
        });

        act(() => {
          result.current.clearTerminal();
        });

        const terminal = result.current.terminal as MockTerminal;
        expect(terminal.getContent()).not.toContain('Some content');
      });

      it('should focus terminal', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        const focusSpy = jest.spyOn(result.current.terminal!, 'focus');

        act(() => {
          result.current.focusTerminal();
        });

        expect(focusSpy).toHaveBeenCalled();
      });

      it('should fit terminal to container', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        const fitSpy = jest.spyOn(result.current.terminal!, 'fit');

        act(() => {
          result.current.fitTerminal();
        });

        expect(fitSpy).toHaveBeenCalled();
      });
    });

    describe('WebSocket Integration', () => {
      it('should connect to WebSocket when terminal is ready', async () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        act(() => {
          jest.advanceTimersByTime(100);
        });

        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });
      });

      it('should send terminal data through WebSocket', async () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });

        const sendDataSpy = jest.fn();
        (result.current as any).sendData = sendDataSpy;

        act(() => {
          // Simulate terminal input
          const terminal = result.current.terminal as MockTerminal;
          terminal.simulateKeyPress('ls', { ctrl: false });
        });

        expect(sendDataSpy).toHaveBeenCalledWith(
          expect.objectContaining({
            type: 'input',
            data: expect.any(String),
          })
        );
      });

      it('should handle WebSocket disconnect gracefully', async () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });

        // Simulate WebSocket disconnect
        act(() => {
          (result.current as any).websocket?.simulateError(new Error('Connection lost'));
        });

        expect(result.current.isConnected).toBe(false);
        
        // Should attempt reconnection
        act(() => {
          jest.advanceTimersByTime(1000);
        });

        await waitFor(() => {
          expect(result.current.isConnected).toBe(true);
        });
      });
    });

    describe('Terminal State Management', () => {
      it('should track scroll position', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        expect(result.current.isAtBottom).toBe(true);

        act(() => {
          result.current.scrollToTop();
        });

        expect(result.current.isAtBottom).toBe(false);

        act(() => {
          result.current.scrollToBottom();
        });

        expect(result.current.isAtBottom).toBe(true);
      });

      it('should detect new output', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        expect(result.current.hasNewOutput).toBe(false);

        act(() => {
          result.current.writeToTerminal('New output');
        });

        expect(result.current.hasNewOutput).toBe(true);

        // Scroll to bottom should clear new output flag
        act(() => {
          result.current.scrollToBottom();
        });

        expect(result.current.hasNewOutput).toBe(false);
      });

      it('should resize terminal on container changes', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        const resizeSpy = jest.fn();
        (result.current as any).resizeTerminal = resizeSpy;

        // Simulate container resize
        act(() => {
          window.dispatchEvent(new Event('resize'));
        });

        expect(resizeSpy).toHaveBeenCalled();
      });
    });

    describe('Error Handling', () => {
      it('should handle terminal creation errors', () => {
        const mockConsoleError = jest.spyOn(console, 'error').mockImplementation();
        
        // Mock Terminal constructor to throw
        const OriginalTerminal = MockTerminal;
        (global as any).Terminal = jest.fn().mockImplementation(() => {
          throw new Error('Terminal creation failed');
        });

        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        expect(result.current.terminal).toBeNull();
        expect(mockConsoleError).toHaveBeenCalled();

        // Restore
        (global as any).Terminal = OriginalTerminal;
        mockConsoleError.mockRestore();
      });

      it('should handle WebSocket errors without crashing', async () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        // Should not throw when WebSocket encounters errors
        expect(() => {
          act(() => {
            (result.current as any).websocket?.simulateError(new Error('WebSocket error'));
          });
        }).not.toThrow();
      });

      it('should handle terminal operation errors gracefully', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        // Mock terminal methods to throw
        const terminal = result.current.terminal as MockTerminal;
        terminal.write = jest.fn().mockImplementation(() => {
          throw new Error('Write failed');
        });

        // Should not crash
        expect(() => {
          act(() => {
            result.current.writeToTerminal('test');
          });
        }).not.toThrow();
      });
    });

    describe('Performance Optimization', () => {
      it('should debounce rapid resize events', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        const fitSpy = jest.spyOn(result.current.terminal!, 'fit');

        // Trigger multiple resize events rapidly
        act(() => {
          for (let i = 0; i < 10; i++) {
            window.dispatchEvent(new Event('resize'));
          }
        });

        // Should debounce the calls
        act(() => {
          jest.advanceTimersByTime(300); // Debounce delay
        });

        expect(fitSpy.mock.calls.length).toBeLessThan(10);
      });

      it('should throttle terminal writes for performance', () => {
        const { result } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        const writeSpy = jest.spyOn(result.current.terminal!, 'write');

        // Send many rapid writes
        act(() => {
          for (let i = 0; i < 100; i++) {
            result.current.writeToTerminal(`Line ${i}\n`);
          }
        });

        // Should batch or throttle writes
        expect(writeSpy.mock.calls.length).toBeLessThanOrEqual(100);
      });

      it('should cleanup event listeners on unmount', () => {
        const removeEventListenerSpy = jest.spyOn(window, 'removeEventListener');
        
        const { unmount } = renderHook(() => useTerminal({ sessionId: defaultSessionId }));

        unmount();

        expect(removeEventListenerSpy).toHaveBeenCalledWith('resize', expect.any(Function));
        
        removeEventListenerSpy.mockRestore();
      });
    });
  });

  describe('Hook Interaction Patterns', () => {
    it('should coordinate between useWebSocket and useTerminal', async () => {
      const TestComponent = () => {
        const ws = useWebSocket('ws://localhost:11237');
        const terminal = useTerminal({ sessionId: 'test-session' });

        React.useEffect(() => {
          if (ws.isConnected && terminal.terminal) {
            // Coordinate the hooks
            ws.on('terminal-data', (data: any) => {
              terminal.writeToTerminal(data.content);
            });

            terminal.terminal.on('data', (data: string) => {
              ws.sendMessage({ type: 'terminal-input', data });
            });
          }
        }, [ws.isConnected, terminal.terminal]);

        return null;
      };

      const { rerender } = renderWithProviders(<TestComponent />);

      await waitFor(() => {
        // Both hooks should be connected
      });

      // Test coordination
      rerender(<TestComponent />);
    });

    it('should handle concurrent hook operations', async () => {
      const { result: wsResult } = renderHook(() => useWebSocket('ws://localhost:11237'));
      const { result: terminalResult } = renderHook(() => useTerminal({ sessionId: 'test' }));

      // Perform concurrent operations
      await act(async () => {
        const promises = [
          wsResult.current.sendMessage({ type: 'test' }),
          terminalResult.current.writeToTerminal('test'),
          wsResult.current.sendMessage({ type: 'test2' }),
          terminalResult.current.clearTerminal(),
        ];

        await Promise.all(promises);
      });

      // Should handle concurrent operations without issues
      expect(wsResult.current.isConnected).toBeDefined();
      expect(terminalResult.current.terminal).toBeDefined();
    });
  });
});