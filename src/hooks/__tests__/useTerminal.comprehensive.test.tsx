import { renderHook, act, waitFor } from '@testing-library/react';
import { useTerminal } from '../useTerminal';
import { Terminal } from '@xterm/xterm';
import { SerializeAddon } from '@xterm/addon-serialize';
import { useWebSocket } from '../useWebSocket';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-serialize');
jest.mock('../useWebSocket');
jest.mock('@/lib/state/store');

// Mock Terminal class
const mockTerminal = {
  cols: 80,
  rows: 24,
  element: {
    querySelector: jest.fn(() => ({
      scrollTop: 0,
      scrollHeight: 1000,
      clientHeight: 500,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    })),
  },
  open: jest.fn(),
  write: jest.fn(),
  clear: jest.fn(),
  focus: jest.fn(),
  dispose: jest.fn(),
  loadAddon: jest.fn(),
  onData: jest.fn(),
  onResize: jest.fn(),
  scrollCleanup: jest.fn(),
};

const mockSerializeAddon = {
  serialize: jest.fn(() => 'serialized content'),
};

const mockWebSocket = {
  sendData: jest.fn(),
  resizeTerminal: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
};

const mockStore = {
  setError: jest.fn(),
  setLoading: jest.fn(),
};

describe('useTerminal', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    
    (Terminal as jest.Mock).mockImplementation(() => mockTerminal);
    (SerializeAddon as jest.Mock).mockImplementation(() => mockSerializeAddon);
    (useWebSocket as jest.Mock).mockReturnValue(mockWebSocket);
    (useAppStore as jest.Mock).mockReturnValue(mockStore);
    
    // Reset terminal mock state
    mockTerminal.cols = 80;
    mockTerminal.rows = 24;
    
    // Mock requestAnimationFrame
    global.requestAnimationFrame = jest.fn((cb) => {
      cb(0);
      return 0;
    });
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  describe('Initialization', () => {
    it('should initialize with default options', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      expect(result.current).toBeDefined();
      expect(result.current.terminalRef).toBeDefined();
      expect(result.current.isConnected).toBe(true);
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
    });

    it('should accept custom config', () => {
      const customConfig = {
        fontSize: 16,
        fontFamily: 'Custom Font',
        theme: 'light' as const,
      };

      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
        config: customConfig,
      }));

      expect(result.current).toBeDefined();
    });

    it('should accept onData callback', () => {
      const onDataMock = jest.fn();

      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
        onData: onDataMock,
      }));

      expect(result.current).toBeDefined();
    });
  });

  describe('Terminal Creation', () => {
    beforeEach(() => {
      // Mock DOM element
      const mockContainer = document.createElement('div');
      jest.spyOn(document, 'createElement').mockReturnValue(mockContainer);
    });

    it('should wait for backend terminal configuration', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      // Terminal should not be created initially without backend config
      expect(Terminal).not.toHaveBeenCalled();
      expect(result.current.terminal).toBeNull();
    });

    it('should create terminal when backend config is received', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      // Mock container ref
      const mockContainer = document.createElement('div');
      Object.defineProperty(result.current.terminalRef, 'current', {
        value: mockContainer,
        writable: true,
      });

      // Simulate receiving backend terminal config
      const terminalConfigHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-config'
      )?.[1];

      await act(async () => {
        terminalConfigHandler({
          sessionId: 'test-session',
          cols: 120,
          rows: 30,
        });
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalled();
      });
    });

    it('should recreate terminal when dimensions change', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const mockContainer = document.createElement('div');
      Object.defineProperty(result.current.terminalRef, 'current', {
        value: mockContainer,
        writable: true,
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-config'
      )?.[1];

      // First config
      await act(async () => {
        terminalConfigHandler({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Second config with different dimensions
      await act(async () => {
        terminalConfigHandler({
          sessionId: 'test-session',
          cols: 120,
          rows: 30,
        });
      });

      await waitFor(() => {
        expect(mockTerminal.dispose).toHaveBeenCalled();
      });
    });
  });

  describe('Terminal Configuration', () => {
    it('should use backend terminal configuration', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const mockContainer = document.createElement('div');
      Object.defineProperty(result.current.terminalRef, 'current', {
        value: mockContainer,
        writable: true,
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-config'
      )?.[1];

      await act(async () => {
        terminalConfigHandler({
          sessionId: 'test-session',
          cols: 100,
          rows: 40,
        });
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(expect.objectContaining({
          cols: 100,
          rows: 40,
        }));
      });
    });

    it('should apply custom theme configuration', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
        config: {
          fontSize: 16,
          fontFamily: 'Custom Font',
        },
      }));

      const mockContainer = document.createElement('div');
      Object.defineProperty(result.current.terminalRef, 'current', {
        value: mockContainer,
        writable: true,
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-config'
      )?.[1];

      await act(async () => {
        terminalConfigHandler({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      await waitFor(() => {
        expect(Terminal).toHaveBeenCalledWith(expect.objectContaining({
          fontSize: 16,
          fontFamily: 'Custom Font',
        }));
      });
    });
  });

  describe('Terminal Operations', () => {
    beforeEach(async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const mockContainer = document.createElement('div');
      Object.defineProperty(result.current.terminalRef, 'current', {
        value: mockContainer,
        writable: true,
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-config'
      )?.[1];

      await act(async () => {
        terminalConfigHandler({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });
    });

    it('should write data to terminal', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.writeToTerminal('Hello World');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Hello World');
    });

    it('should clear terminal', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('should focus terminal', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });

    it('should handle fitTerminal as no-op', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      // Should not throw error
      expect(() => {
        act(() => {
          result.current.fitTerminal();
        });
      }).not.toThrow();
    });

    it('should destroy terminal', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.destroyTerminal();
      });

      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });

  describe('Scrolling Behavior', () => {
    it('should scroll to bottom', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.scrollToBottom();
      });

      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });

    it('should scroll to top', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.scrollToTop();
      });

      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });

    it('should track scroll position', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      // Initial state should be at bottom
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
    });

    it('should show new output indicator when not at bottom', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      // Simulate terminal data when not at bottom
      const terminalDataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      // Mock viewport to simulate not being at bottom
      const mockViewport = {
        scrollTop: 100,
        scrollHeight: 1000,
        clientHeight: 500,
      };
      
      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      await act(async () => {
        terminalDataHandler({
          sessionId: 'test-session',
          data: 'New output\n',
        });
      });

      // Should show new output indicator
      await waitFor(() => {
        expect(result.current.hasNewOutput).toBe(true);
      });
    });
  });

  describe('Data Handling', () => {
    it('should handle terminal input data', async () => {
      const onDataMock = jest.fn();
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
        onData: onDataMock,
      }));

      const mockContainer = document.createElement('div');
      Object.defineProperty(result.current.terminalRef, 'current', {
        value: mockContainer,
        writable: true,
      });

      const terminalConfigHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-config'
      )?.[1];

      await act(async () => {
        terminalConfigHandler({
          sessionId: 'test-session',
          cols: 80,
          rows: 24,
        });
      });

      // Simulate terminal input
      const onDataCallback = mockTerminal.onData.mock.calls[0][0];
      
      act(() => {
        onDataCallback('test input');
      });

      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session', 'test input');
      expect(onDataMock).toHaveBeenCalledWith('test input');
    });

    it('should handle incoming terminal data', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const terminalDataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      await act(async () => {
        terminalDataHandler({
          sessionId: 'test-session',
          data: 'Output from server',
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('Output from server');
    });

    it('should handle terminal errors', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const terminalErrorHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-error'
      )?.[1];

      await act(async () => {
        terminalErrorHandler({
          sessionId: 'test-session',
          error: 'Command not found',
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\x1b[31mCommand not found\x1b[0m\r\n');
    });

    it('should handle connection changes', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const connectionChangeHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'connection-change'
      )?.[1];

      await act(async () => {
        connectionChangeHandler(true);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        '\r\n\x1b[90m[\x1b[32mConnected\x1b[90m]\x1b[0m\r\n'
      );

      await act(async () => {
        connectionChangeHandler(false);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        '\r\n\x1b[90m[\x1b[31mDisconnected\x1b[90m]\x1b[0m\r\n'
      );
    });
  });

  describe('Cleanup', () => {
    it('should cleanup event listeners on unmount', () => {
      const { unmount } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      unmount();

      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('connection-change', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-config', expect.any(Function));
    });

    it('should cleanup terminal on unmount', () => {
      const { result, unmount } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      unmount();

      // Cleanup should be called
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });

    it('should handle scroll cleanup', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.destroyTerminal();
      });

      expect(mockTerminal.scrollCleanup).toHaveBeenCalled();
    });
  });

  describe('Edge Cases', () => {
    it('should handle terminal operations when terminal is null', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      // Terminal should be null initially
      expect(result.current.terminal).toBeNull();

      // Operations should not throw
      expect(() => {
        act(() => {
          result.current.writeToTerminal('test');
          result.current.clearTerminal();
          result.current.focusTerminal();
          result.current.destroyTerminal();
        });
      }).not.toThrow();
    });

    it('should handle data for different session IDs', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'session-1',
      }));

      const terminalDataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      await act(async () => {
        terminalDataHandler({
          sessionId: 'session-2', // Different session
          data: 'Should not be written',
        });
      });

      expect(mockTerminal.write).not.toHaveBeenCalledWith('Should not be written');
    });

    it('should handle missing viewport element', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      mockTerminal.element.querySelector.mockReturnValue(null);

      // Should not throw
      expect(() => {
        act(() => {
          result.current.scrollToBottom();
          result.current.scrollToTop();
        });
      }).not.toThrow();
    });

    it('should handle terminal without element', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      mockTerminal.element = null;

      // Should not throw
      expect(() => {
        act(() => {
          result.current.scrollToBottom();
          result.current.scrollToTop();
        });
      }).not.toThrow();
    });

    it('should handle empty or whitespace data', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const terminalDataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      await act(async () => {
        terminalDataHandler({
          sessionId: 'test-session',
          data: '   \n  \t  ', // Whitespace only
        });
      });

      // Should not set hasNewOutput for whitespace-only content
      expect(result.current.hasNewOutput).toBe(false);
    });
  });

  describe('Performance', () => {
    it('should handle rapid data updates efficiently', async () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      const terminalDataHandler = mockWebSocket.on.mock.calls.find(
        call => call[0] === 'terminal-data'
      )?.[1];

      // Send multiple rapid updates
      for (let i = 0; i < 100; i++) {
        await act(async () => {
          terminalDataHandler({
            sessionId: 'test-session',
            data: `Line ${i}\n`,
          });
        });
      }

      expect(mockTerminal.write).toHaveBeenCalledTimes(100);
    });

    it('should use requestAnimationFrame for scroll operations', () => {
      const { result } = renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      act(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      });

      expect(global.requestAnimationFrame).toHaveBeenCalledTimes(2);
    });
  });
});
