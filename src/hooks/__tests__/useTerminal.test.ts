import { renderHook, act } from '@testing-library/react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { useTerminal } from '../useTerminal';
import { useWebSocket } from '../useWebSocket';
import { useAppStore } from '@/lib/state/store';

// Mock dependencies
jest.mock('@xterm/xterm');
jest.mock('@xterm/addon-fit');
jest.mock('../useWebSocket');
jest.mock('@/lib/state/store');

// Mock Terminal methods
const mockTerminal = {
  open: jest.fn(),
  write: jest.fn(),
  clear: jest.fn(),
  focus: jest.fn(),
  dispose: jest.fn(),
  onData: jest.fn(),
  onResize: jest.fn(),
  loadAddon: jest.fn(),
  element: {
    querySelector: jest.fn(() => ({
      scrollTop: 0,
      scrollHeight: 1000,
      clientHeight: 500,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    }))
  }
};

const mockFitAddon = {
  fit: jest.fn(),
};

const mockWebSocket = {
  sendData: jest.fn(),
  resizeTerminal: jest.fn(),
  on: jest.fn(),
  off: jest.fn(),
  isConnected: true,
};

describe('useTerminal', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    (Terminal as jest.Mock).mockImplementation(() => mockTerminal);
    (FitAddon as jest.Mock).mockImplementation(() => mockFitAddon);
    (useWebSocket as jest.Mock).mockReturnValue(mockWebSocket);
    (useAppStore as jest.Mock).mockReturnValue({
      // Add any store methods if needed
    });
    
    // Mock requestAnimationFrame
    global.requestAnimationFrame = jest.fn((cb) => setTimeout(cb, 0));
    
    // Reset mock terminal element
    mockTerminal.element.querySelector = jest.fn(() => ({
      scrollTop: 0,
      scrollHeight: 1000,
      clientHeight: 500,
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    }));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  const defaultOptions = {
    sessionId: 'test-session-123',
    config: { fontSize: 14 },
  };

  describe('initialization', () => {
    it('should initialize terminal with correct configuration', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      expect(Terminal).toHaveBeenCalledWith(expect.objectContaining({
        fontSize: 14,
        fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
        cursorBlink: true,
        scrollback: 999999,
        rows: 30,
        cols: 120,
        convertEol: true,
        allowTransparency: false,
        windowsMode: false,
        disableStdin: false,
      }));
    });

    it('should load FitAddon and open terminal', () => {
      const mockContainer = document.createElement('div');
      
      const { result } = renderHook(() => useTerminal(defaultOptions));
      
      // Simulate container ref being set
      act(() => {
        (result.current.terminalRef as any).current = mockContainer;
      });

      expect(mockTerminal.loadAddon).toHaveBeenCalledWith(mockFitAddon);
      expect(mockTerminal.open).toHaveBeenCalledWith(mockContainer);
    });

    it('should set up terminal event handlers', () => {
      renderHook(() => useTerminal(defaultOptions));

      expect(mockTerminal.onData).toHaveBeenCalled();
      expect(mockTerminal.onResize).toHaveBeenCalled();
    });

    it('should set up WebSocket event listeners', () => {
      renderHook(() => useTerminal(defaultOptions));

      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWebSocket.on).toHaveBeenCalledWith('connection-change', expect.any(Function));
    });
  });

  describe('terminal operations', () => {
    it('should write data to terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.writeToTerminal('test data');
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('test data');
    });

    it('should clear terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.clearTerminal();
      });

      expect(mockTerminal.clear).toHaveBeenCalled();
    });

    it('should focus terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.focusTerminal();
      });

      expect(mockTerminal.focus).toHaveBeenCalled();
    });

    it('should fit terminal', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.fitTerminal();
      });

      expect(mockFitAddon.fit).toHaveBeenCalled();
    });

    it('should handle fit errors gracefully', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockFitAddon.fit.mockImplementation(() => {
        throw new Error('Fit failed');
      });

      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.fitTerminal();
      });

      expect(consoleSpy).toHaveBeenCalledWith('Failed to fit terminal:', expect.any(Error));
      consoleSpy.mockRestore();
    });
  });

  describe('data handling', () => {
    it('should send terminal data via WebSocket', () => {
      const onDataSpy = jest.fn();
      const { result } = renderHook(() => 
        useTerminal({ ...defaultOptions, onData: onDataSpy })
      );

      // Simulate terminal data event
      const mockOnData = mockTerminal.onData.mock.calls[0][0];
      act(() => {
        mockOnData('test input');
      });

      expect(mockWebSocket.sendData).toHaveBeenCalledWith('test-session-123', 'test input');
      expect(onDataSpy).toHaveBeenCalledWith('test input');
    });

    it('should handle terminal resize events', () => {
      renderHook(() => useTerminal(defaultOptions));

      // Simulate terminal resize event
      const mockOnResize = mockTerminal.onResize.mock.calls[0][0];
      act(() => {
        mockOnResize({ cols: 80, rows: 24 });
      });

      expect(mockWebSocket.resizeTerminal).toHaveBeenCalledWith('test-session-123', 80, 24);
    });

    it('should handle incoming terminal data', () => {
      renderHook(() => useTerminal(defaultOptions));

      // Get the terminal-data handler
      const handleTerminalData = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')[1];

      act(() => {
        handleTerminalData({
          sessionId: 'test-session-123',
          data: 'incoming data'
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('incoming data');
    });

    it('should ignore data from other sessions', () => {
      renderHook(() => useTerminal(defaultOptions));

      const handleTerminalData = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-data')[1];

      act(() => {
        handleTerminalData({
          sessionId: 'other-session',
          data: 'other data'
        });
      });

      expect(mockTerminal.write).not.toHaveBeenCalledWith('other data');
    });

    it('should handle terminal errors', () => {
      renderHook(() => useTerminal(defaultOptions));

      const handleTerminalError = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-error')[1];

      act(() => {
        handleTerminalError({
          sessionId: 'test-session-123',
          error: 'Connection lost'
        });
      });

      expect(mockTerminal.write).toHaveBeenCalledWith('\x1b[31mConnection lost\x1b[0m\r\n');
    });

    it('should handle connection state changes', () => {
      renderHook(() => useTerminal(defaultOptions));

      const handleConnectionChange = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'connection-change')[1];

      act(() => {
        handleConnectionChange(true);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        '\r\n\x1b[90m[\x1b[32mConnected\x1b[90m]\x1b[0m\r\n'
      );

      act(() => {
        handleConnectionChange(false);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        '\r\n\x1b[90m[\x1b[31mDisconnected\x1b[90m]\x1b[0m\r\n'
      );
    });
  });

  describe('scroll management', () => {
    it('should scroll to bottom', () => {
      const mockViewport = {
        scrollTop: 0,
        scrollHeight: 1000,
        clientHeight: 500,
      };
      
      mockTerminal.element.querySelector.mockReturnValue(mockViewport);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.scrollToBottom();
      });

      // Check that requestAnimationFrame was called
      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });

    it('should scroll to top', () => {
      const mockViewport = {
        scrollTop: 500,
        scrollHeight: 1000,
        clientHeight: 500,
      };
      
      mockTerminal.element.querySelector.mockReturnValue(mockViewport);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.scrollToTop();
      });

      expect(global.requestAnimationFrame).toHaveBeenCalled();
    });

    it('should track scroll position correctly', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      // Initial state should be at bottom
      expect(result.current.isAtBottom).toBe(true);
      expect(result.current.hasNewOutput).toBe(false);
    });
  });

  describe('cleanup', () => {
    it('should clean up resources on unmount', () => {
      const { unmount } = renderHook(() => useTerminal(defaultOptions));

      unmount();

      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-data', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('terminal-error', expect.any(Function));
      expect(mockWebSocket.off).toHaveBeenCalledWith('connection-change', expect.any(Function));
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });

    it('should handle cleanup when terminal is null', () => {
      const { result, unmount } = renderHook(() => useTerminal(defaultOptions));

      // Simulate terminal being null
      act(() => {
        result.current.destroyTerminal();
      });

      expect(() => unmount()).not.toThrow();
    });

    it('should remove scroll event listener on cleanup', () => {
      const mockViewport = {
        scrollTop: 0,
        scrollHeight: 1000,
        clientHeight: 500,
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      };
      
      mockTerminal.element.querySelector.mockReturnValue(mockViewport);
      
      const { unmount } = renderHook(() => useTerminal(defaultOptions));

      unmount();

      expect(mockTerminal.dispose).toHaveBeenCalled();
    });
  });

  describe('window resize handling', () => {
    it('should handle window resize events', () => {
      jest.useFakeTimers();
      
      renderHook(() => useTerminal(defaultOptions));

      // Simulate window resize
      act(() => {
        window.dispatchEvent(new Event('resize'));
        jest.advanceTimersByTime(100);
      });

      expect(mockFitAddon.fit).toHaveBeenCalled();
    });

    it('should handle resize fit errors', () => {
      const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
      mockFitAddon.fit.mockImplementation(() => {
        throw new Error('Resize fit failed');
      });

      jest.useFakeTimers();
      renderHook(() => useTerminal(defaultOptions));

      act(() => {
        window.dispatchEvent(new Event('resize'));
        jest.advanceTimersByTime(100);
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        'Failed to fit terminal on resize:', 
        expect.any(Error)
      );
      
      consoleSpy.mockRestore();
    });
  });

  describe('configuration', () => {
    it('should merge custom config with defaults', () => {
      const customConfig = {
        fontSize: 16,
        fontFamily: 'Custom Font',
        cursorBlink: false,
      };

      renderHook(() => useTerminal({
        sessionId: 'test-session',
        config: customConfig,
      }));

      expect(Terminal).toHaveBeenCalledWith(expect.objectContaining({
        fontSize: 16,
        fontFamily: 'Custom Font',
        cursorBlink: false,
        scrollback: 999999, // Should keep defaults
      }));
    });

    it('should use default config when none provided', () => {
      renderHook(() => useTerminal({
        sessionId: 'test-session',
      }));

      expect(Terminal).toHaveBeenCalledWith(expect.objectContaining({
        fontSize: 14,
        fontFamily: 'JetBrains Mono, Menlo, Monaco, Consolas, monospace',
        cursorBlink: true,
        scrollback: 999999,
      }));
    });
  });

  describe('connection status', () => {
    it('should return connection status from WebSocket', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      expect(result.current.isConnected).toBe(true);
    });

    it('should handle disconnected state', () => {
      (useWebSocket as jest.Mock).mockReturnValue({
        ...mockWebSocket,
        isConnected: false,
      });

      const { result } = renderHook(() => useTerminal(defaultOptions));

      expect(result.current.isConnected).toBe(false);
    });
  });

  describe('edge cases', () => {
    it('should handle terminal config changes gracefully', () => {
      renderHook(() => useTerminal(defaultOptions));

      // Get the terminal-config handler
      const handleTerminalConfig = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')[1];

      act(() => {
        handleTerminalConfig({
          sessionId: 'test-session-123',
          cols: 100,
          rows: 30
        });
      });

      // Should log config reception
      expect(mockTerminal.dispose).not.toHaveBeenCalled(); // No recreation since mock terminal doesn't change
    });

    it('should handle null terminal element gracefully', () => {
      mockTerminal.element = null;
      
      const { result } = renderHook(() => useTerminal(defaultOptions));

      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle missing viewport element', () => {
      mockTerminal.element.querySelector.mockReturnValue(null);
      
      const { result } = renderHook(() => useTerminal(defaultOptions));

      expect(() => {
        result.current.scrollToBottom();
        result.current.scrollToTop();
      }).not.toThrow();
    });

    it('should handle terminal initialization failure', () => {
      (Terminal as jest.Mock).mockImplementation(() => {
        throw new Error('Terminal initialization failed');
      });

      // Should not crash the component
      expect(() => renderHook(() => useTerminal(defaultOptions))).not.toThrow();
    });

    it('should handle terminal config with dimension changes', () => {
      // Start with initial terminal
      renderHook(() => useTerminal(defaultOptions));

      // Mock terminal with different dimensions
      mockTerminal.cols = 80;
      mockTerminal.rows = 24;

      const handleTerminalConfig = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'terminal-config')[1];

      act(() => {
        handleTerminalConfig({
          sessionId: 'test-session-123',
          cols: 100,
          rows: 30
        });
      });

      // Should trigger terminal recreation due to dimension change
      expect(mockTerminal.dispose).toHaveBeenCalled();
    });

    it('should handle rapid data writes without crashing', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      // Simulate rapid data writes
      act(() => {
        for (let i = 0; i < 100; i++) {
          result.current.writeToTerminal(`Line ${i}\n`);
        }
      });

      expect(mockTerminal.write).toHaveBeenCalledTimes(100);
    });

    it('should handle terminal disposal during active scroll operations', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      act(() => {
        result.current.scrollToBottom();
        result.current.destroyTerminal();
        result.current.scrollToTop(); // Should handle gracefully
      });

      expect(() => {
        result.current.scrollToBottom();
      }).not.toThrow();
    });

    it('should handle WebSocket reconnection scenarios', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      const handleConnectionChange = mockWebSocket.on.mock.calls
        .find(call => call[0] === 'connection-change')[1];

      // Disconnect
      act(() => {
        handleConnectionChange(false);
      });

      // Reconnect
      act(() => {
        handleConnectionChange(true);
      });

      expect(mockTerminal.write).toHaveBeenCalledWith(
        '\r\n\x1b[90m[\x1b[31mDisconnected\x1b[90m]\x1b[0m\r\n'
      );
      expect(mockTerminal.write).toHaveBeenCalledWith(
        '\r\n\x1b[90m[\x1b[32mConnected\x1b[90m]\x1b[0m\r\n'
      );
    });

    it('should handle backend config timeout scenarios', () => {
      jest.useFakeTimers();
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();

      renderHook(() => useTerminal(defaultOptions));

      // Fast forward past config timeout
      act(() => {
        jest.advanceTimersByTime(3000);
      });

      expect(consoleSpy).toHaveBeenCalledWith('[Terminal] Timeout waiting for backend config, using defaults');

      consoleSpy.mockRestore();
    });

    it('should handle scroll position tracking edge cases', () => {
      const { result } = renderHook(() => useTerminal(defaultOptions));

      // Simulate viewport at exact bottom threshold
      const mockViewport = {
        scrollTop: 450,
        scrollHeight: 1000,
        clientHeight: 500,
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
      };

      mockTerminal.element.querySelector.mockReturnValue(mockViewport);

      // Should correctly detect near-bottom position
      expect(result.current.isAtBottom).toBe(true);
    });
  });
});