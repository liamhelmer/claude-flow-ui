import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '../useTerminal';
import { useWebSocket } from '../useWebSocket';
import { useAppStore } from '@/lib/state/store';
import { Terminal } from '@xterm/xterm';

// Mock dependencies
jest.mock('../useWebSocket');
jest.mock('@/lib/state/store');
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');

const mockUseWebSocket = useWebSocket as jest.MockedFunction<typeof useWebSocket>;
const mockUseAppStore = useAppStore as jest.MockedFunction<typeof useAppStore>;

describe('useTerminal - Comprehensive Enhanced Tests', () => {
  let mockSendData: jest.Mock;
  let mockResizeTerminal: jest.Mock;
  let mockOn: jest.Mock;
  let mockOff: jest.Mock;
  let mockTerminal: jest.Mocked<Terminal>;

  beforeEach(() => {
    jest.clearAllMocks();
    
    mockSendData = jest.fn();
    mockResizeTerminal = jest.fn();
    mockOn = jest.fn();
    mockOff = jest.fn();

    mockUseWebSocket.mockReturnValue({
      sendData: mockSendData,
      resizeTerminal: mockResizeTerminal,
      on: mockOn,
      off: mockOff,
      isConnected: true,
      connected: true,
      connecting: false,
      connect: jest.fn(),
      disconnect: jest.fn(),
      sendMessage: jest.fn(),
      createSession: jest.fn(),
      destroySession: jest.fn(),
      listSessions: jest.fn(),
    });

    mockUseAppStore.mockReturnValue({
      setError: jest.fn(),
      setLoading: jest.fn(),
    });

    // Mock Terminal constructor and methods
    mockTerminal = {
      open: jest.fn(),
      write: jest.fn(),
      dispose: jest.fn(),
      focus: jest.fn(),
      clear: jest.fn(),
      onData: jest.fn(),
      loadAddon: jest.fn(),
      cols: 80,
      rows: 24,
      element: {
        querySelector: jest.fn(() => ({
          addEventListener: jest.fn(),
          removeEventListener: jest.fn(),
          scrollTop: 0,
          scrollHeight: 1000,
          clientHeight: 400,
        })),
      },
    } as any;

    (Terminal as jest.MockedClass<typeof Terminal>).mockImplementation(() => mockTerminal);

    // Setup DOM environment
    Object.defineProperty(HTMLElement.prototype, 'scrollTop', {
      value: 0,
      writable: true,
    });

    Object.defineProperty(HTMLElement.prototype, 'scrollHeight', {
      value: 1000,
      writable: true,
    });

    Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
      value: 400,
      writable: true,
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Terminal Initialization', () => {
    it('should not create terminal without backend config', () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      expect(Terminal).not.toHaveBeenCalled();
      expect(result.current.terminal).toBeNull();
    });

    it('should create terminal when backend config is received', async () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalled();
        expect(result.current.terminal).toBe(mockTerminal);
      });
    });

    it('should recreate terminal when dimensions change', async () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      // Initial config
      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledTimes(1);
      });

      // Change dimensions
      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 120, rows: 30 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.dispose).toHaveBeenCalled();
        expect(Terminal).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('Data Handling', () => {
    beforeEach(async () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalled();
      });
    });

    it('should handle incoming terminal data', () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const dataHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
        if (dataHandler) {
          dataHandler({ sessionId: 'test-session', data: 'Hello World' });
        }
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Hello World');
    });

    it('should handle terminal errors', () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const errorHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-error')?.[1];
        if (errorHandler) {
          errorHandler({ sessionId: 'test-session', error: 'Test error' });
        }
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\x1b[31mTest error\x1b[0m\r\n');
    });

    it('should send user input to backend', async () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      const dataCallback = mockTerminal.onData.mock.calls[0][0];
      act(() => {
        dataCallback('test input');
      });

      expect(mockSendData).toHaveBeenCalledWith('test-session', 'test input');
    });
  });

  describe('Scroll Management', () => {
    beforeEach(async () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalled();
      });
    });

    it('should detect when user is at bottom', async () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      await waitFor(() => {
        expect(result.current.isAtBottom).toBe(true);
      });
    });

    it('should scroll to bottom when requested', async () => {
      jest.useFakeTimers();
      
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      const mockViewport = {
        scrollTop: 100,
        scrollHeight: 1000,
        clientHeight: 400,
      };

      mockTerminal.element!.querySelector = jest.fn(() => mockViewport);

      act(() => {
        result.current.scrollToBottom();
        jest.runAllTimers();
      });

      expect(mockViewport.scrollTop).toBe(1000);
    });

    it('should scroll to top when requested', async () => {
      jest.useFakeTimers();
      
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      const mockViewport = {
        scrollTop: 500,
        scrollHeight: 1000,
        clientHeight: 400,
      };

      mockTerminal.element!.querySelector = jest.fn(() => mockViewport);

      act(() => {
        result.current.scrollToTop();
        jest.runAllTimers();
      });

      expect(mockViewport.scrollTop).toBe(0);
    });
  });

  describe('Connection Management', () => {
    it('should handle connection status changes', () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const connectionHandler = mockOn.mock.calls.find(call => call[0] === 'connection-change')?.[1];
        if (connectionHandler) {
          connectionHandler(true);
        }
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\r\n\x1b[90m[\x1b[32mConnected\x1b[90m]\x1b[0m\r\n');

      act(() => {
        const connectionHandler = mockOn.mock.calls.find(call => call[0] === 'connection-change')?.[1];
        if (connectionHandler) {
          connectionHandler(false);
        }
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\r\n\x1b[90m[\x1b[31mDisconnected\x1b[90m]\x1b[0m\r\n');
    });
  });

  describe('Terminal Actions', () => {
    beforeEach(async () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalled();
      });
    });

    it('should write to terminal', () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.writeToTerminal('test output');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('test output');
    });

    it('should clear terminal', () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('should focus terminal', () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });
  });

  describe('Cleanup', () => {
    it('should clean up event listeners on unmount', () => {
      const { unmount } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      const offCalls = mockOff.mock.calls.length;

      unmount();

      expect(mockOff).toHaveBeenCalledTimes(offCalls + 4); // 4 event types
    });

    it('should dispose terminal on unmount', async () => {
      const { result, unmount } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalled();
      });

      unmount();

      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });

  describe('Edge Cases', () => {
    it('should handle missing viewport element', () => {
      const { result } = renderHook(() => 
        useTerminal({ sessionId: 'test-session' })
      );

      mockTerminal.element!.querySelector = jest.fn(() => null);

      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle data for wrong session', () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      act(() => {
        const dataHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-data')?.[1];
        if (dataHandler) {
          dataHandler({ sessionId: 'wrong-session', data: 'Hello World' });
        }
      });

      expect(mockTerminal.write).not.toHaveBeenCalled();
    });

    it('should handle config without terminal instance', () => {
      renderHook(() => useTerminal({ sessionId: 'test-session' }));

      expect(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      }).not.toThrow();
    });
  });

  describe('Custom Configuration', () => {
    it('should use custom config options', async () => {
      const customConfig = {
        fontSize: 16,
        fontFamily: 'Courier New',
        theme: 'light' as const,
      };

      renderHook(() => 
        useTerminal({ sessionId: 'test-session', config: customConfig })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(
          expect.objectContaining({
            fontSize: 16,
            fontFamily: 'Courier New',
          })
        );
      });
    });

    it('should call onData callback when provided', async () => {
      const onDataCallback = jest.fn();

      renderHook(() => 
        useTerminal({ sessionId: 'test-session', onData: onDataCallback })
      );

      act(() => {
        const configHandler = mockOn.mock.calls.find(call => call[0] === 'terminal-config')?.[1];
        if (configHandler) {
          configHandler({ sessionId: 'test-session', cols: 80, rows: 24 });
        }
      });

      await waitFor(() => {
        expect(mockTerminal.onData).toHaveBeenCalled();
      });

      const dataCallback = mockTerminal.onData.mock.calls[0][0];
      act(() => {
        dataCallback('test input');
      });

      expect(onDataCallback).toHaveBeenCalledWith('test input');
    });
  });
});